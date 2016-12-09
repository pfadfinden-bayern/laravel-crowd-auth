<?php namespace Crowd\Auth\Providers;

use Illuminate\Auth\Guard;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\ServiceProvider;


class CrowdAuthServiceProvider extends ServiceProvider
{
    
    protected $defer = false;
    
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
        
        $this->app['auth']->extend('CrowdAuth', function ($app) {
            $provider = new CrowdAuthUserServiceProvider($this->app['CrowdApi']);
            
            return new Guard($provider, $app['session.store']);
        });
        
        // When Laravel logs out, logout the Crowd token using Crowd API
        $events->listen('auth.logout', function ($user) {
            $this->app['CrowdApi']->ssoInvalidateToken($user->getRememberToken());
        });
    }
    
    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        //
    }
    
    public function provides()
    {
        return ['CrowdAuth'];
    }
    
}
