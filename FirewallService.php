<?php

/*
 * This file is part of the Firewall Service for Silex framework.
 *
 * (c) Alessandro Perta
 */

namespace RedefineLab\FirewallService;

use Silex\Application;

/*
 * The firewall service class.
 *
 * @author Alessandro Perta
 */
class FirewallService {

    const ALLOWED = 'allowed';
    const DENIED = 'denied';
    const ERROR_SETUP_NOT_COMPLETE = '$role or defaultRoute not set.';
    const ERROR_ALLOWED_DENIED = 'Cannot allow and deny at the same time : %s';

    private $app;
    private $fullUris;
    private $defaultUri = '';
    private $defaultUrisForRole = array();
    private $restrictedUris = array();

    /**
     * Firewall service.
     *
     * @param Application $app The current Application instance.
     * @param boolean $fullUris If generated redirect responses use full URIs.
     * Default to false.
     * @param string $host The host to which redirects point to. Defaults to
     * current host. If a host is provided, the $fullUris parameter value has
     * no effect at all.
     */
    public function __construct(Application $app, $fullUris = false, $host = '') {
        $this->app = $app;
        $this->fullUris = $fullUris;
        $this->host = $host;
    }

    /**
     * Sets the general default route.
     *
     * @param string $namedRoute The default named route (value of the "bind" method
     * called on a controller route).
     * @param array $routeParams An array of route params. Please DO NOT use regex.
     * @return type
     */
    public function setDefaultRoute($namedRoute, $routeParams = array()) {
        $uri = $this->createUriForRoute($namedRoute, $routeParams);
        return $this->setDefaultUri($uri);
    }

    /**
     * Sets the general default URI.
     *
     * @param string $uri The default URI.
     * @return FirewallService
     */
    private function setDefaultUri($uri) {
        $this->defaultUri = $uri;
        return $this;
    }

    /**
     * Returns the general default URI.
     *
     * @return string The general default URI.
     */
    public function getDefaultUri() {
        return $this->defaultUri;
    }

    /**
     * Sets a default route for a provided role.
     *
     * @param string $role The role of the current user.
     * @param string $namedRoute The default named route (value of the "bind" method
     * called on a controller route).
     * @param array $routeParams An array of route params. Please DO NOT use regex.
     * @return FirewallService
     */
    public function setDefaultRouteForRole($role, $namedRoute, array $routeParams = array()) {
        $uri = $this->createUriForRoute($namedRoute, $routeParams);
        return $this->setDefaultUriForRole($role, $uri);
    }

    /**
     * Sets a default URI for a provided role.
     *
     * @param string $role The role of the current user.
     * @param string $uri The URI to which the provided user is redirected to when
     * visiting a denied URI.
     * @return FirewallService
     */
    private function setDefaultUriForRole($role, $uri) {
        $this->defaultUrisForRole[$role] = $uri;
        return $this;
    }

    /**
     * Returns the URI to which the provided user is redirected to when
     * visiting a denied URI.
     *
     * @param string $role The role of the current user.
     * @return string The URI to which the provided user is redirected to when
     * visiting a denied URI.
     */
    public function getDefaultUriForRole($role = null) {
        if ($role != null && array_key_exists($role, $this->defaultUrisForRole)) {
            return $this->defaultUrisForRole[$role];
        }
        return $this->defaultUri;
    }

    /**
     * Sets a URI or part of a URI to allow. Note that calling this method
     * with the same URI will overwrite current allowed roles.
     *
     * @param mixed $allowedRoles A string or an array of roles to allow.
     * @param string $uri An URI or part of an URI to allow. Accepts regex.
     * @return FirewallService The current FirewallService instance.
     */
    public function setAllowedUri($allowedRoles, $uri) {

        // checking if URI has not allowed and denied roles at the same time
        if (array_key_exists($uri, $this->restrictedUris) && array_key_exists(self::DENIED, $this->restrictedUris[$uri])) {
            throw new \Exception(sprintf(self::ERROR_ALLOWED_DENIED, $uri));
        }

        $this->restrictedUris[$uri][self::ALLOWED] = $allowedRoles;

        // if a single role is passed, we put it in an array
        if (!is_array($allowedRoles)) {
            $allowedRoles = array($allowedRoles);
        }

        // setting allowed URI
        $this->restrictedUris[$uri][self::ALLOWED] = $allowedRoles;
        return $this;
    }

    /**
     * Sets an allowed route for one or many roles.
     *
     * @param mixed $allowedRoles A string or an array of roles to allow.
     * @param string $namedRoute The named route (value of the "bind" method
     * called on a controller route) to allow.
     * @param array $routeParams An array of route params. Accepts regex.
     * @return FirewallService The current FirewallService instance.
     */
    public function setAllowedRoute($allowedRoles, $namedRoute, array $routeParams = array()) {
        $uri = $this->createUriForRoute($namedRoute, $routeParams);
        return $this->setAllowedUri($allowedRoles, $uri);
    }

    /**
     * Sets a URI or part of a URI to deny. Note that calling this method
     * with the same URI will overwrite current denied roles.
     *
     * @param mixed $deniedRoles A string or an array of roles to deny.
     * @param string $uri An URI or part of an URI to restrict. Accepts regex.
     * @return FirewallService The current FirewallService instance.
     */
    public function setDeniedUri($deniedRoles, $uri) {

        // checking if URI has not allowed and denied roles at the same time
        if (array_key_exists($uri, $this->restrictedUris) && array_key_exists(self::ALLOWED, $this->restrictedUris[$uri])) {
            throw new \Exception(sprintf(self::ERROR_ALLOWED_DENIED, $uri));
        }

        // if a single role is passed, we put it in an array
        if (!is_array($deniedRoles)) {
            $deniedRoles = array($deniedRoles);
        }

        // setting denied URI
        $this->restrictedUris[$uri][self::DENIED] = $deniedRoles;
        return $this;
    }

    /**
     * Sets a denied route for one or many roles.
     *
     * @param mixed $deniedRoles A string or an array of roles to deny.
     * @param string $namedRoute The named route (value of the "bind" method
     * called on a controller route) to restrict.
     * @param array $routeParams An array of route params. Accepts regex.
     * @return FirewallService The current FirewallService instance.
     */
    public function setDeniedRoute($deniedRoles, $namedRoute, array $routeParams = array()) {
        $uri = $this->createUriForRoute($namedRoute, $routeParams);
        return $this->setDeniedUri($deniedRoles, $uri);
    }

    /**
     * @return array An array of all restricted URIs with their associated
     * allowed or denied roles
     */
    public function getRestrictedUris() {
        return $this->restrictedUris;
    }

    /**
     * Runs the firewall. Note that you must return this method in order for
     * redirect to work.
     *
     * @param string $role
     * @param string $uri A URI that has to be checked for permissions. If null,
     * this methods check the actual requested URI.
     * @return mixed True if success or Silex Response if requested URI is
     * restricted for current role.
     */
    public function run($role, $uri = null) {

        // checking if the role of current user is provided and general default
        // URI exists
        if (!isset($role) || $this->defaultUri == '') {
            throw new \Exception(self::ERROR_SETUP_NOT_COMPLETE);
        }

        // returning the requesedt URI according to config (full URL or URI)
        if ($this->fullUris == true) {
            $requestUri = $this->app['request']->getUri();
        } else {
            $requestUri = $this->app['request']->getRequestUri();
        }

        // if a URI is provided as method parameter, we use it instead
        // (mainly used for test purposes)
        if (null != $uri) {
            $requestUri = $uri;
        }

        // if requested URI is restricted for provided role, we redirect
        if ($this->isRestrictedUriForRole($requestUri, $role)) {
            return $this->redirectToDefault($role);
        }

        // else everythings fine, open sesame !
        return true;
    }

    /**
     * Initializes all object properties to null.
     */
    public function reset() {
        $this->defaultUri = '';
        $this->defaultUrisForRole = array();
        $this->restrictedUris = array();
    }

    /**
     * Returns a URI using Silex's URL generator.
     *
     * @param string $namedRoute The named route (value of the "bind" method
     * called on a controller route).
     * @param array $routeParams An array of route params. Values can be
     * regex.
     * @return string The URL decoded string reprensenting the route. Note that
     * the returned string is URL decoded since it is the string that is parsed
     * by the firewall via a preg_match.
     */
    private function createUriForRoute($namedRoute, array $routeParams) {
        return urldecode($this->app['url_generator']->generate($namedRoute, $routeParams, $this->fullUris));
    }

    /**
     * Checks if current requested URI is restricted for role.
     *
     * @param string $requestUri The requested URI.
     * @param string $role The role of the current user.
     * @return boolean
     */
    private function isRestrictedUriForRole($requestUri, $role) {

        foreach ($this->restrictedUris as $restrictedUri => $rule) {

            // defining if current request URI is a restricted URI
            $isRestrictedUri = preg_match("@$restrictedUri@", $requestUri);

            // defining if role is allowed
            if (array_key_exists(self::ALLOWED, $rule)) {
                $isAllowedRole = in_array($role, $rule[self::ALLOWED]);
            } else {
                $isAllowedRole = true;
            }

            // defining if role is denied
            $isDeniedRole = (array_key_exists(self::DENIED, $rule) && in_array($role, $rule[self::DENIED]));

            // if requested URI is not allowed or denied for this role, we return true
            if ($isRestrictedUri && (!$isAllowedRole || $isDeniedRole)) {
                return true;
            }
        }

        // no URI generated an error, URI is allowed
        return false;
    }

    /**
     * Redirects to a default URL, set by setDefaultRoute and
     * setDefaultRouteForRole methods.
     *
     * @param string $role the role of the current user.
     * @return type A Silex HTTP response.
     */
    private function redirectToDefault($role) {

        // if a default URI is set for current role, we use it
        if (array_key_exists($role, $this->defaultUrisForRole)) {
            $redirectUri = $this->defaultUrisForRole[$role];
        } else {

            // else we use the general default URI which is always set
            $redirectUri = $this->defaultUri;
        }

        // using host if set
        if ($this->host != '') {
            $redirectUri = $this->host . $redirectUri;
        }

        // return the Response
        return $this->app->redirect($redirectUri);
    }

}