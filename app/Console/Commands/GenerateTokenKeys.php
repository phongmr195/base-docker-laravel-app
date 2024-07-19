<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;

class GenerateTokenKeys extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'app:generate-token-keys';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Command to generate public and private keys for JWT.';

    /**
     * Execute the console command.
     */
    public function handle(): void
    {
        // Ask for the passphrase
        $passphrase = $this->secret('Enter the passphrase for the private key');
        $passphraseConfirm = $this->secret('Confirm the passphrase for the private key');

        if ($passphrase !== $passphraseConfirm) {
            $this->error('The passphrases do not match.');
            return;
        }

        // Generate the private key
        $privateKey = Storage::path('jwt/private.pem');
        $command = "openssl genrsa -passout pass:{$passphrase} -out {$privateKey}";
        exec($command);

        // Generate the public key
        $publicKey = Storage::path('jwt/public.pem');
        $command = "openssl rsa -in {$privateKey} -passin pass:{$passphrase} -pubout -out {$publicKey}";
        exec($command);


        $this->info('Public and private keys have been generated successfully.');
    }
}
