<?php

namespace RedefineLab\FirewallService;

use Silex\Application;
use Silex\ServiceProviderInterface;

class FirewallServiceProvider implements ServiceProviderInterface {

    public function register(Application $app) {
        $app['firewall'] = $app->share(function () use ($app) {
                    $host = (isset($app['firewall.host'])) ? $app['firewall.host'] : '';
                    $fullUris = (isset($app['firewall.fulluris'])) ? $app['firewall.fulluris'] : false;
                    return new FirewallService($app, $fullUris, $host);
                });
    }

}