<?php namespace Crowd\Auth\Providers;

use Illuminate\Auth\Guard;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\ServiceProvider;

/**
 * Class CrowdAuthServiceProvider
 *
 * @package Crowd\Auth\Providers
 */
class CrowdAuthServiceProvider extends ServiceProvider
{
    
    /**
     * Bootstrap the application services.
     *
     * @param Dispatcher $events
     */
    public function boot(Dispatcher $events)
    {
        $this->publishes([
            __DIR__ . '/../Database/Migrations/' => base_path('/database/migrations'),
        ], 'migrations');
    
        \Auth::provider('crowd', function ($app) {
            return new CrowdAuthUserServiceProvider($app['config']);
        });
    
        // When a Laravel user logs out, logout the Crowd token using Crowd API
        $events->listen('auth.logout', function ($user) {
            $this->app['crowd.api']->ssoInvalidateToken($user->sso_token);
        });
    }
}
