Laravel Crowd Auth
==================

A simple way to implement Atlassian Crowd Authentication into your application.

**SUPPORTED VERSIONS:** Atlassian Crowd 2.1 and later versions only.

## Quick start

### Laravel 5.3.x

In the `require` key of `composer.json` file add the following

    "mglinski/laravel-crowd-auth": "*"

Run the Composer update comand

    $ composer update

In your `config/app.php` add `Crowd\Auth\CrowdAuthServiceProvider'` to the end of the `providers` array

```php
'providers' => [
    ...

    Crowd\Auth\CrowdAuthApiServiceProvider::class,
    Crowd\Auth\CrowdAuthServiceProvider::class,
],
```

Now generate the Crowd Auth migrations (make sure you have your database configuration set up):

    $ php artisan vendor:publish --tag=migrations

This will setup three tables - `crowd_auth_users`, `crowd_auth_users` and `crowd_auth_group_auth_user`.

Now publish the config files for this package:

    $ php artisan vendor:publish --tag=config

Once the configuration is published go to your `config/crowd_auth.php` and configure your Atlassian Crowd settings.

After you have configured your Atlassian Crowd settings you need to change the `driver` setting in `config/auth.php` to:

```php
'driver' => 'crowd-auth',
```

Once all this is completed you can simply use `Auth::Attempt()` and it will attempt to login using your Atlassian Crowd server.
