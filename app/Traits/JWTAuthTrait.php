<?php

namespace App\Traits;

use App\Helpers\JwtHelper;

use Illuminate\Support\Facades\DB;

trait JWTAuthTrait
{
    public function createToken(string $action = 'authToken', string $expiration = '+1 week'): string
    {
        // Ensure $this->uuid is a non-empty string
        if (empty($this->uuid)) {
            return '';
        }

        $config = JwtHelper::getJwtConfiguration();
        $date = new \DateTimeImmutable();
        $uniqueID = uniqid();

        // Generate the token with appropriate claims
        $token = $config->builder()
            ->issuedBy(config('jwt.issuer')) // Configures the issuer (iss claim)
            ->permittedFor(config('jwt.audience')) // Configures the audience (aud claim)
            ->identifiedBy($uniqueID) // Configures the id (jti claim)
            ->relatedTo($this->uuid) // Configures the subject (sub claim)
            ->issuedAt($date) // Configures the time that the token was issued (iat claim)
            ->canOnlyBeUsedAfter($date) // Configures the time that the token can be used (nbf claim)
            ->expiresAt($date->modify($expiration)) // Configures the expiration time of the token (exp claim)
            ->getToken($config->signer(), $config->signingKey()); // Retrieves the generated token

        // insert the token record in database
        DB::table('jwt_tokens')->insert([
            'user_uuid' => $this->uuid,
            'unique_id' => $uniqueID,
            'description' => $action." ".$this->email,
            'permissions' => null,
            'expires_at' => $date->modify($expiration),
            'last_used_at' => null,
            'created_at' => $date,
            'updated_at' => $date,
        ]);

        $this->token = $token->toString();

        return $token->toString();
    }

    public function destroyToken(string $tokenString): void
    {
        if (empty($tokenString)) {
            throw new \Exception('Token string is empty');
        }

        // Parse token
        $config = JwtHelper::getJwtConfiguration();
        $token = $config->parser()->parse($tokenString);

        if (!method_exists($token, 'claims')) {
            throw new \Exception("Invalid Token", 1);
        }

        // Check if the token belongs to the user
        $userUUID = $token->claims()->get('sub');
        $uniqueID = $token->claims()->get('jti');

        if (!$userUUID || !$uniqueID || $this->uuid !== $userUUID) {
            throw new \Exception('Invalid token');
        }

        if(
            // Delete the token record
            !DB::table('jwt_tokens')->where([
                'unique_id' => $uniqueID,
                'user_uuid' => $this->uuid
            ])->delete()
        ) {
            throw new \Exception('Invalid token');
        }
    }
}