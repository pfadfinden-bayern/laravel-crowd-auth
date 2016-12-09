<?php namespace Crowd\Auth\Providers;

use Crowd\Auth\Api\CrowdAPI;
use Illuminate\Support\ServiceProvider;

class CrowdApiServiceProvider extends ServiceProvider
{
    
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/../Config/crowd_auth.php' => config_path('crowd_auth.php'),
        ], 'config');
    }
    
    /**
     * Register the application services.
     *
     * @return void
     * @throws \RuntimeException
     */
    public function register()
    {
        // Use a singleton here, we only need one instance of the api object
        $this->app->bind('crowd-api', function ($app) {
            $config = $app['config']->get('crowd_auth');
            
            return new CrowdAPI(
                $config['url'],
                $config['app_name'],
                $config['app_password']
            );
        });
        
    }
    
    public function provides()
    {
        return ['crowd-api'];
    }
    
}
