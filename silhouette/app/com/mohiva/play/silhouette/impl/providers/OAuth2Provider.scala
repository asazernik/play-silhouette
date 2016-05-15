/**
 * Original work: SecureSocial (https://github.com/jaliss/securesocial)
 * Copyright 2013 Jorge Aliss (jaliss at gmail dot com) - twitter: @jaliss
 *
 * Derivative work: Silhouette (https://github.com/mohiva/play-silhouette)
 * Modifications Copyright 2015 Mohiva Organisation (license at mohiva dot com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mohiva.play.silhouette.impl.providers

import java.net.URLEncoder._

import com.mohiva.play.silhouette.api._
import com.mohiva.play.silhouette.api.exceptions._
import com.mohiva.play.silhouette.api.util.{ Base64, ExtractableRequest }
import com.mohiva.play.silhouette.impl.exceptions.{ AccessDeniedException, UnexpectedResponseException }
import com.mohiva.play.silhouette.impl.providers.OAuth2Provider._
import play.api.libs.functional.syntax._
import play.api.libs.json._
import play.api.libs.ws.WSResponse
import play.api.mvc._

import scala.concurrent.{ ExecutionContext, Future }
import scala.util.{ Failure, Success, Try }

/**
 * The Oauth2 info.
 *
 * @param accessToken  The access token.
 * @param tokenType    The token type.
 * @param expiresIn    The number of seconds before the token expires.
 * @param refreshToken The refresh token.
 * @param params       Additional params transported in conjunction with the token.
 */
case class OAuth2Info(
  accessToken: String,
  tokenType: Option[String] = None,
  expiresIn: Option[Int] = None,
  refreshToken: Option[String] = None,
  params: Option[Map[String, String]] = None,
  userState: Option[String] = None) extends SocialAuthInfo

/**
 * The Oauth2 info companion object.
 */
object OAuth2Info extends OAuth2Constants {

  /**
   * Converts the JSON into a [[com.mohiva.play.silhouette.impl.providers.OAuth2Info]] object.
   */
  implicit val infoReads = (
    (__ \ AccessToken).read[String] and
    (__ \ TokenType).readNullable[String] and
    (__ \ ExpiresIn).readNullable[Int] and
    (__ \ RefreshToken).readNullable[String]
  )((accessToken: String, tokenType: Option[String], expiresIn: Option[Int], refreshToken: Option[String]) =>
      new OAuth2Info(accessToken, tokenType, expiresIn, refreshToken)
    )
}

/**
 * Base implementation for all OAuth2 providers.
 */
trait OAuth2Provider extends SocialProvider with OAuth2Constants with Logger {

  /**
   * The type of the auth info.
   */
  type A = OAuth2Info

  /**
   * The settings type.
   */
  type Settings = OAuth2Settings

  /**
   * The state provider implementation.
   */
  protected val stateProvider: OAuth2StateProvider

  /**
   * A list with headers to send to the API.
   */
  protected val headers: Seq[(String, String)] = Seq()

  /**
   * Starts the authentication process.
   *
   * @param request The current request.
   * @tparam B The type of the request body.
   * @return Either a Result or the auth info from the provider.
   */
  def authenticate[B]()(implicit request: ExtractableRequest[B]): Future[Either[Result, OAuth2Info]] = {
    if (request.extractString(Error).orElse(request.extractString(Code)).nonEmpty)
      continueAuthentication()
    else initiateAuthentication(None).map(Left(_))
  }

  /**
   * Redirects the user to the provider's OAuth endpoint
   *
   * @param userState A piece of state to include in the resulting AuthInfo in case of success
   * @param request The initial request
   * @return A Result (usually a Redirect) to send to the browser which will start it on the appropriate flow
   */
  def initiateAuthentication[B](userState: Option[String])(implicit request: ExtractableRequest[B]): Future[Result] = {
    stateProvider.build.map { csrfState =>

      val stateParamValue = Json.obj() ++
        (csrfState.serialize match {
          case csrfString if csrfString.isEmpty => Json.obj()
          case csrfString => Json.obj(CsrfState -> csrfString)
        }) ++
        (userState match {
          case None => Json.obj()
          case Some(reallyUserState)  => Json.obj(UserState -> reallyUserState)
        })

      val stateParam = if (stateParamValue.value.isEmpty) List() else List(State -> Base64.encode(stateParamValue))
      val params = settings.scope.foldLeft(List(
        (ClientID, settings.clientID),
        (RedirectURI, resolveCallbackURL(settings.redirectURL)),
        (ResponseType, Code)) ++ stateParam ++ settings.authorizationParams.toList) {
        case (p, s) => (Scope, s) :: p
      }
      val encodedParams = params.map { p => encode(p._1, "UTF-8") + "=" + encode(p._2, "UTF-8") }
      val url = settings.authorizationURL.getOrElse {
        throw new ConfigurationException(AuthorizationURLUndefined.format(id))
      } + encodedParams.mkString("?", "&", "")
      val redirect = stateProvider.publish(Results.Redirect(url), csrfState)
      logger.debug("[Silhouette][%s] Use authorization URL: %s".format(id, settings.authorizationURL))
      logger.debug("[Silhouette][%s] Redirecting to: %s".format(id, url))
      redirect
    }
  }

  /**
   * Checks a callback from
   *
   * @param request The request
   * @tparam B
   * @return Either a Result to continue the flow or the AuthInfo from the provider.
   */
  def continueAuthentication[B]()(implicit request: ExtractableRequest[B]): Future[Either[Result, OAuth2Info]] = {
    (request.extractString(Error), request.extractString(Code)) match {

      // The authorization server returned an error instead of a code
      case (Some(error), None) => Future.failed {
        error match {
          case e @ AccessDenied => new AccessDeniedException(AuthorizationError.format(id, e))
          case e                => new UnexpectedResponseException(AuthorizationError.format(id, e))
        }
      }

      // We're being redirected back from the authorization server with the access code
      case (None, Some(code)) => stateProvider.validate(request.extractString(State)).flatMap { state =>
        getAccessToken(code).map(oauth2Info => Right(oauth2Info))
      }

      case _ => Future.failed(new UnexpectedResponseException(InvalidInfoFormat.format(id,
        "exactly one of code or error should have been set in callback")))
    }
  }

  /**
   * Gets the access token.
   *
   * @param code    The access code.
   * @param request The current request.
   * @return The info containing the access token.
   */
  protected def getAccessToken(code: String)(implicit request: RequestHeader): Future[OAuth2Info] = {
    httpLayer.url(settings.accessTokenURL).withHeaders(headers: _*).post(Map(
      ClientID -> Seq(settings.clientID),
      ClientSecret -> Seq(settings.clientSecret),
      GrantType -> Seq(AuthorizationCode),
      Code -> Seq(code),
      RedirectURI -> Seq(resolveCallbackURL(settings.redirectURL))) ++ settings.accessTokenParams.mapValues(Seq(_))).flatMap { response =>
      logger.debug("[Silhouette][%s] Access token response: [%s]".format(id, response.body))
      Future.fromTry(buildInfo(response))
    }
  }

  /**
   * Builds the OAuth2 info from response.
   *
   * @param response The response from the provider.
   * @return The OAuth2 info on success, otherwise a failure.
   */
  protected def buildInfo(response: WSResponse): Try[OAuth2Info] = {
    response.json.validate[OAuth2Info].asEither.fold(
      error => Failure(new UnexpectedResponseException(InvalidInfoFormat.format(id, error))),
      info => Success(info)
    )
  }

  case class OAuth2StateParam(
    csrfState: Option[String], // actually mandatory, but we want to handle the error better than JsonParseException
    userState: Option[String]
  )

  implicit val oauth2StateParamFormat = Json.format[OAuth2StateParam]

  /**
    * Gets the state from request the after the provider has redirected back from the authorization server
    * with the access code.
    *
    * @param request The request.
    * @tparam B The type of the request body.
    * @return The OAuth2 state on success, otherwise a failure.
    */
  private def extractOAuth2State[B](implicit request: ExtractableRequest[B]) = Try {
    request.extractString(State).map { oauth2StateBase64 =>
      Json.parse(Base64.decode(oauth2StateBase64)).as[OAuth2StateParam]
    }
  }
}

/**
 * The OAuth2Provider companion object.
 */
object OAuth2Provider extends OAuth2Constants {

  /**
   * The error messages.
   */
  val AuthorizationURLUndefined = "[Silhouette][%s] Authorization URL is undefined"
  val AuthorizationError = "[Silhouette][%s] Authorization server returned error: %s"
  val InvalidInfoFormat = "[Silhouette][%s] Cannot build OAuth2Info because of invalid response format: %s"

  /**
   * Constants used in the Silhouette-specific format of the OAuth2 state
   */
  val CsrfState = "csrf_state"
  val UserState = "user_state"
}

/**
 * The OAuth2 constants.
 */
trait OAuth2Constants {

  val ClientID = "client_id"
  val ClientSecret = "client_secret"
  val RedirectURI = "redirect_uri"
  val Scope = "scope"
  val ResponseType = "response_type"
  val State = "state"
  val GrantType = "grant_type"
  val AuthorizationCode = "authorization_code"
  val AccessToken = "access_token"
  val Error = "error"
  val Code = "code"
  val TokenType = "token_type"
  val ExpiresIn = "expires_in"
  val Expires = "expires"
  val RefreshToken = "refresh_token"
  val AccessDenied = "access_denied"
}

/**
 * The OAuth2 state.
 *
 * This is to prevent the client for CSRF attacks as described in the OAuth2 RFC.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-10.12
 */
trait OAuth2State {

  /**
   * Checks if the state is expired. This is an absolute timeout since the creation of
   * the state.
   *
   * @return True if the state is expired, false otherwise.
   */
  def isExpired: Boolean

  /**
   * Returns a serialized value of the state.
   *
   * @return A serialized value of the state.
   */
  def serialize: String
}

/**
 * Provides state for authentication providers.
 */
trait OAuth2StateProvider {

  /**
   * The type of the state implementation.
   */
  type State <: OAuth2State

  /**
   * Builds the state.
   *
   * @param request The current request.
   * @param ec      The execution context to handle the asynchronous operations.
   * @tparam B The type of the request body.
   * @return The build state.
   */
  def build[B](implicit request: ExtractableRequest[B], ec: ExecutionContext): Future[State]

  /**
   * Validates the provider and the client state.
   *
   * @param request The current request.
   * @param ec      The execution context to handle the asynchronous operations.
   * @tparam B The type of the request body.
   * @return The state on success, otherwise an failure.
   */
  def validate[B](maybeProviderState: Option[String])(implicit request: ExtractableRequest[B], ec: ExecutionContext): Future[State]

  /**
   * Publishes the state to the client.
   *
   * @param result  The result to send to the client.
   * @param state   The state to publish.
   * @param request The current request.
   * @tparam B The type of the request body.
   * @return The result to send to the client.
   */
  def publish[B](result: Result, state: State)(implicit request: ExtractableRequest[B]): Result
}

/**
 * The OAuth2 settings.
 *
 * @param authorizationURL    The authorization URL provided by the OAuth provider.
 * @param accessTokenURL      The access token URL provided by the OAuth provider.
 * @param redirectURL         The redirect URL to the application after a successful authentication on the OAuth
 *                            provider. The URL can be a relative path which will be resolved against the current
 *                            request's host.
 * @param apiURL              The URL to fetch the profile from the API. Can be used to override the default URL
 *                            hardcoded in every provider implementation.
 * @param clientID            The client ID provided by the OAuth provider.
 * @param clientSecret        The client secret provided by the OAuth provider.
 * @param scope               The OAuth2 scope parameter provided by the OAuth provider.
 * @param authorizationParams Additional params to add to the authorization request.
 * @param accessTokenParams   Additional params to add to the access token request.
 * @param customProperties    A map of custom properties for the different providers.
 */
case class OAuth2Settings(
  authorizationURL: Option[String] = None,
  accessTokenURL: String,
  redirectURL: String,
  apiURL: Option[String] = None,
  clientID: String,
  clientSecret: String,
  scope: Option[String] = None,
  authorizationParams: Map[String, String] = Map.empty,
  accessTokenParams: Map[String, String] = Map.empty,
  customProperties: Map[String, String] = Map.empty)
