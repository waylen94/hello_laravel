<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

class TestEncryptionEllipticCurve extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'schedule:testing_elliptic_curve_encryption';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Command description';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        echo "Beigining Testing ECC Algorithm".PHP_EOL.PHP_EOL;

        var_dump(openssl_get_curve_names()); //this is for php > 7.0

        






    }
}
