<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

//dealing with asn1 format
use FG\ASN1\Universal\Sequence;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\BitString;
//obtain needed ECC Library
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Primitives\Point;
use Mdanter\Ecc\Primitives\PointInterface;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\Ecc\Serializer\Point\CompressedPointSerializer;
use Mdanter\Ecc\Serializer\Util\CurveOidMapper;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;

use App\Console\Commands\ECIES_Scheme_Experiment;


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
        //ECIES is a pretty generate paradigm for generation an ephemeral ECDH key, 
        //doing a kex with someone's public key, 
        //runnign the result through a KDF,
        // and then using that as a symmetric key to actually encrypt that data.

        //corresponded public and private key retrieved from Google Tink Library
       $private_key_simulation = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjj"
       ."chHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx"
       ."9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm";

       $public_key_simulation = "BOdoXP+9Aq473SnGwg3JU1aiNpsd9vH2ognq4PtDtlLGa3Kj8TPf+jaQNPyDSkh3JUhiS0KyrrlWhAgNZKHYF2Y=";

       $Google_provided_public_Key = "{\n"
        ."  \"keys\": [\n"
        ."    {\n"
        . "      \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPYnHwS8uegWAewQtlxizmLFynw"
        . "HcxRT1PK07cDA6/C4sXrVI1SzZCUx8U8S0LjMrT6ird/VW7be3Mz6t/srtRQ==\",\n"
        . "      \"protocolVersion\": \"ECv1\"\n"
        . "    },\n"
        . "    {\n"
        . "      \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM"
        . "43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==\",\n"
        . "      \"keyExpiration\": \""
        . 1542394027316
        . "\",\n"
        . "      \"protocolVersion\": \"ECv2\"\n"
        . "    },\n"
        . "    {\n"
        . "      \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENXvYqxD5WayKYhuXQevdGdLA8i"
        . "fV4LsRS2uKvFo8wwyiwgQHB9DiKzG6T/P1Fu9Bl7zWy/se5Dy4wk1mJoPuxg==\",\n"
        . "      \"keyExpiration\": \""
        . 1542394027316
        . "\",\n"
        . "      \"protocolVersion\": \"ECv2SigningOnly\"\n"
        . "    },\n"
        . "  ],\n"
        . "}";

    $GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PUBLIC_KEY_X509_BASE64 = "";

    $ephemeral_public_key_signedmessage_received = "";

    $standard_decrypted_message = "plaintext";

    $RECIPIENT_ID = "someRecipient";

    $signed_message = "{"
        . "\"protocolVersion\":\"ECv1\","
        . "\"signedMessage\":"
        . ("\"{"
            . "\\\"tag\\\":\\\"ZVwlJt7dU8Plk0+r8rPF8DmPTvDiOA1UAoNjDV+SqDE\\\\u003d\\\","
            . "\\\"ephemeralPublicKey\\\":\\\"BPhVspn70Zj2Kkgu9t8+ApEuUWsI/zos5whGCQBlgOkuYagOis7"
            . "qsrcbQrcprjvTZO3XOU+Qbcc28FSgsRtcgQE\\\\u003d\\\","
            . "\\\"encryptedMessage\\\":\\\"12jUObueVTdy\\\"}\",")
        . "\"signature\":\"MEQCIDxBoUCoFRGReLdZ/cABlSSRIKoOEFoU3e27c14vMZtfAiBtX3pGMEpnw6mSAbnagC"
        . "CgHlCk3NcFwWYEyxIE6KGZVA\\u003d\\u003d\"}";


        echo "Beigining Testing ECC Algorithm".PHP_EOL.PHP_EOL;
        
        //1. receive all needed resource for decryption -1. ephemeral_publick_key; -2. private_key -3. encrypted_message 
        $signed_message= json_decode($signed_message);
        $ephemeral_public_key = json_decode($signed_message->signedMessage)->ephemeralPublicKey;
        $private_key = $private_key_simulation;
        $encrypted_message = json_decode($signed_message->signedMessage)->encryptedMessage;

        //Testing all the needed message retrieve successful
        // echo $private_key.$ephemeral_public_key.$encrypted_message.PHP_EOL;

        //2. Generating shared Key 
        $this->encrypter = new ECIESEncrypter($public_key, $private_key, ECIESEncrypter::JSON_FORMAT);

        //Testing generated Shared Key

        //3. HASH_HMAC_KDF_SHA256 GENERATING 512 BIT SYMETRIC KEY and split for symmetrical Key 256 + MAC_Verify_Key 256  
        // $hardcode_label_info = ord('G')ord('o').ord('o').ord('g)'.ord('l').ord('e');
        $hardcode_label_info =  iconv("UTF-8", "ASCII", 'Google');
        
        //Testing generated symmetric Key

        //4. Decrypte using AES_256_CTR 


        //Testing Decrypted_text
        







    }


    public function resource_version1(){
        //Resource version 1 
        $form_data_str = 'random string generated for testing';
        $algorithm = 'aes-256-ctr';
        $sKey = '1lgs2gjwjPZpeqUHlYD9ktJBXfsuH5al'; 
        $iv = '0000000000000000';
        // Encrypt
        $encrypted_data = bin2hex(openssl_encrypt($form_data_str, $algorithm, $sKey, OPENSSL_RAW_DATA, $iv));
        echo "Encrypted: ".$encrypted_data.PHP_EOL;
        //Decrypt
        $decrypted_data = openssl_decrypt(pack('H*', $encrypted_data), $algorithm, $sKey, OPENSSL_RAW_DATA, $iv);
        echo "<br>Decrypted: ".$decrypted_data.PHP_EOL;
        //resource version 1 finished
    }
}


