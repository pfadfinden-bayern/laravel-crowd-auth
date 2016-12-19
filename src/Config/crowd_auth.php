<?php

/*
 * This file is part of CrowdAuth
 *
 * (c) Daniel McAssey <hello@glokon.me>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

return array(
    
    /*
    |--------------------------------------------------------------------------
    | Crowd Auth: Crowd URL
    |--------------------------------------------------------------------------
    | Please specify the URL to your crowd service for authentication, it must
    | NOT end in a forward slash and be a publicly accesible URL.
    */
    'url' => env('CROWD_AUTH_APP_URL', 'http://crowd.example.com:8080/crowd'),
    
    /*
    |--------------------------------------------------------------------------
    | Crowd Auth: Application Name
    |--------------------------------------------------------------------------
    | Here is where you specify your application name that you use for your
    | crowd application.
    */
    'app_name' => env('CROWD_AUTH_APP_NAME', 'crowd-app-name'),
    
    /*
    |--------------------------------------------------------------------------
    | Crowd Auth: Application Password
    |--------------------------------------------------------------------------
    | Here is where you specify your password that you use for your crowd
    | application.
    */
    'app_password' => env('CROWD_AUTH_APP_PASSWORD', 'crowd-app-password'),
    
    /*
    |--------------------------------------------------------------------------
    | Crowd Auth: SSO Refresh Interval
    |--------------------------------------------------------------------------
    | Here is where you specify your how often we should check in with the SSO
    | provider and update groups and permissions. Value expressed in seconds.
    */
    'refresh_interval' => 60 * 5,
    
    /*
    |--------------------------------------------------------------------------
    | Crowd Auth: Usable User Groups [******* FEATURE-DISABLED *********]
    |--------------------------------------------------------------------------
    |
    | Here is where you define each of the groups that have access to your
    | application.
    |
    | EDIT: THIS DOES NOTHING FOR NOW
    */
    'app_groups' => array(
    
        'app-administrators',
    
        'app-users',

    ),

);
