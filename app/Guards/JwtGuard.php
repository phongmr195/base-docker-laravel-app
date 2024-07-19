<?php

namespace App\Guards;

use Lcobucci\JWT\Configuration;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;

use App\Helpers\JwtHelper;

use App\Models\User;
use Illuminate\Support\Facades\Hash;

class JwtGuard implements Guard
{
    /**
     * @var User | null $user The user.
     * @var UserProvider $provider The user provider.
     * @var Request $request The request.
     * @var Configuration $config The JWT configuration.
     */
    protected $user;
    protected UserProvider $provider;
    protected Request $request;
    protected Configuration $config;

    public function __construct(UserProvider $provider, Request $request)
    {
        // Define the Provide and The Request incoming from the middleware
        $this->provider = $provider;
        $this->request = $request;

        // Define the auth configuration we need in the guard
        $this->config = JwtHelper::getJwtConfiguration();
    }

    // Check if the the user already defined
    public function check()
    {
        return !is_null($this->user());
    }

    public function guest()
    {
        return !$this->check();
    }

    // The process to define the user making the request
    public function user()
    {
        // check if it's already defined to skip the process
        if ($this->hasUser()) {
            return $this->user;
        }

        try {
            // Check if we have the bearer token with the ncoming Request
            $token = $this->request->bearerToken();

            if (!$token) {
                return null;
            }

            // If token exists let's parse it, based on our private/public keys
            $token = $this->config->parser()->parse($token);

            if(!method_exists($token, 'claims')) {
                return null;
            }

            // Check if there are any token constraints
            $constraints = $this->config->validationConstraints();

            if(!empty($constraints)) {
                // If constraints exists let's validate them
                $this->config->validator()->assert($token, ...$constraints);
            }

            // Retrive the user_uuid claim, stop the process if is missing
            $uuid = $token->claims()->get('sub');

            if(!$uuid) {
                return null;
            }

            // Check if user exists with the uuid above
            $user = User::where('uuid', $uuid)->first();

            if(!$user) {
                return null;
            }

            // We set the user matching the records and we validate the token
            $this->setUser($user);
            $this->validateToken($token);

            return $this->user;
        } catch (\Exception $e) {
            return null;
        }
    }

    public function id()
    {
        return $this->user() ? $this->user()->getAuthIdentifier() : null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param array<mixed> $credentials User credentials.
     * @return bool Always returns false, as this method is not applicable for JWT Guard.
     */
    public function validate(array $credentials = []): bool
    {
        // This method is not applicable for JWT Guard
        return false;
    }

    public function hasUser()
    {
        return !is_null($this->user);
    }

    /**
     * Set the user.
     * @param \App\Models\User $user The user to set.
     * @return $this
     */
    public function setUser($user)
    {
        $this->user = $user;
        return $this;
    }

    /**
     * Validate the token
     * @param \Lcobucci\JWT\Token $token The token to destroy.
     * @return void
     * @throws \Exception If the token is invalid.
     */
    private function validateToken($token)
    {
        if (!$this->hasUser()) {
            throw new \Exception('No user set');
        }

        if(!method_exists($token, 'claims')) {
            throw new \Exception('Invalid token');
        }

        // Check if token exists, belong to the user and not expired
        $recordExists = DB::table('jwt_tokens')
                            ->where([
                                'unique_id' => $token->claims()->get('jti'),
                                'user_uuid' => $this->user->uuid
                            ])
                            ->where('expires_at', '>', now())
                            ->exists();

        if(!$recordExists) {
            throw new \Exception('Invalid token');
        }
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     * @param array<mixed> $credentials User credentials.
     * @param bool $remember Whether to remember the user.
     * @return void
     * @throws \Exception If the authentication attempt fails.
     */
    public function attempt(array $credentials = [], $remember = false)
    {
        $user = User::where('email', $credentials['email'])->first();

        if (!$user || !Hash::check($credentials['password'], $user->password)) {
            throw new \Exception(__('auth.failed'));
        } else {
            $this->setUser($user);
        }
    }
}