<?php

namespace App\Console\Commands;
use Illuminate\Console\Command;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Primitives\Point;
use Mdanter\Ecc\Primitives\PointInterface;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\Ecc\Serializer\Point\CompressedPointSerializer;
use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;
use Mdanter\Ecc\Serializer\Util\CurveOidMapper;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Math\GmpMath;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Mdanter\Ecc\Crypto\Key\PublicKey;
use Mdanter\Ecc\Util\NumberSize;

class testGooglePay extends Command{
    const NON_SALT = '00000000000000000000000000000000';
    private $encrypter;
    protected $signature =  'schedule:testGooglePay';

    protected $description =    'Use this command to test GooglePay Ctyprography mechanism:
                                php artisan schedule:testGooglePay';

    public function __construct(){
        parent::__construct();
    }



	public function handle(){
        $execDir = "./"; 
        $hardcode_public_key_addr = 'TEST_KEY_PUB.pem';
        $hardcode_private_key_addr = 'TEST_KEY.pem';
        $GooglePaymentMessagefile = file_get_contents('paymentData.txt', true);
        // $public_key_testing = file_get_contents($hardcode_public_key_addr);
        // $MW_private_key_testing_addr_command = app_path(). '/'.$certDir. 'TEST_KEY.pem';  //execute in command line
        // $MW_private_key_testing_addr_php = '/home/wliu/mwarrior2.0/api/certs/googlepay/'. 'TEST_KEY.pem';  //Eeecute in php
        // $openssl_private_key_resource = openssl_pkey_get_private('file://'.$MW_private_key_testing_addr_php);//     'file://' for openssl
        
        $GooglePaymentMessage = json_decode($GooglePaymentMessagefile);
        $token = json_decode($GooglePaymentMessage->googlePayData->paymentMethodData->tokenizationData->token);
        $signedMessage_decode = json_decode($token->signedMessage);
        $encryptedMessage = $signedMessage_decode->encryptedMessage;  // most hindrance part for decrypting the message
        $mac_tag = $signedMessage_decode->tag;

        $Google_ephemeralPublicKey_origin = $signedMessage_decode->ephemeralPublicKey;
        $Google_ephemeralPublicKey  =  $Google_ephemeralPublicKey_origin ;
        $fileNameEphemeralPublicKey = "ephemeralPublicKey"."key".uniqid();
        $fullPathEphemeralPublicKey = $execDir. $fileNameEphemeralPublicKey;
        if(file_exists($fullPathEphemeralPublicKey)) return false; //later we should 1. operate or 2. return some response insteaded
        $public_key = null;
        $private_key = file_get_contents($hardcode_private_key_addr,true);

        echo "encryptedMessage:  ".$encryptedMessage;
        $ciphertext = base64_decode($encryptedMessage);
        $mac = base64_decode($mac_tag);
        $hardcode_label_info =  iconv("UTF-8", "ASCII", 'Google');
        $google_hkdf_iv = \hex2bin('00000000000000000000000000000000');

        //1. ECDH
        $generator = EccFactory::getNistCurves()->generator256();

        $adapter = EccFactory::getAdapter();
        $pemPub = new PemPublicKeySerializer(new DerPublicKeySerializer());
        $pemPriv = new PemPrivateKeySerializer(new DerPrivateKeySerializer());
        $myPrivateKey = $pemPriv->parse(file_get_contents($hardcode_private_key_addr,true));

        $uncompressed_point_serializer = new UncompressedPointSerializer($adapter);

        $uncompressed_point = $uncompressed_point_serializer->unserialize($generator->getCurve(), bin2hex(base64_decode($Google_ephemeralPublicKey )));
        $Google_ephemeralPublicKey = new PublicKey($adapter, $generator, $uncompressed_point);

        $exchange = $myPrivateKey->createExchange($Google_ephemeralPublicKey);
        $shared = $exchange->calculateSharedKey();
        echo "Shared secret: " . gmp_strval($shared, 10).PHP_EOL;

        //2. Hash_HKDF
        $hardcode_label_info =  iconv("UTF-8", "ASCII", 'Google');
        // $hardcode_label_info = 'Google';
        $salt = str_repeat("\x0", 32);
        $C0 = hex2bin($uncompressed_point_serializer->serialize($uncompressed_point));


        //testing version 1 -- binary with default shared key
        $binary = $generator->getAdapter()->intToFixedSizeString($shared, NumberSize::bnNumBytes($adapter, $generator->getOrder()));
        $generator->getAdapter()->intToString($shared);
        $HKDF_Generated_key= hash_hkdf('sha256',$C0.$binary, 64, $hardcode_label_info, $salt);

        //testing version 3 -- pure string with singlehash=0 mode
        // $shared = $generator->getAdapter()->intToString($shared);
        // $HKDF_Generated_key= hash_hkdf('sha256',$Google_ephemeralPublicKey_origin.$shared, 64, $hardcode_label_info, $salt);
       
        echo "512 bits based Encryption key: " . unpack("H*", $HKDF_Generated_key)[1] . PHP_EOL;

        $kdf_symmetric_key = substr($HKDF_Generated_key, 0, 32);

        //3. AES_256_CTR
        $decrypted = \openssl_decrypt(base64_encode($ciphertext), 'AES-256-CTR', $kdf_symmetric_key, 0, $google_hkdf_iv);

        echo PHP_EOL.PHP_EOL.$decrypted.PHP_EOL;



}


function old_handle(){

            //simulate/hardcode the tokenizationData for testing only
        // $simulated_tokenizationData = array(
        //     'type' => 'PAYMENT_GATEWAY',
        //     'token' => '{"signature":"MEYCIQCcQKP+ieNp4VI6T9aFMnV/TU5P29AdCX+M6HUK0OXxrAIhAK/mInvpW7fkJ3+eiTAnwIf9VJGH51MIiI05n8W+JsbK","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpmA0vkpFJ7uksrkD+4YhHgs44CSnwfj7kRtnDDpfhjo//tFGBE/bwZeMsSduVac76KQk3XeXUcpQ6i0y61Ngzg\\u003d\\u003d\",\"keyExpiration\":\"1582141178278\"}","signatures":["MEYCIQCED90gEkk5HcLNWE9HrGXZEJL+n25Kq2BaLkwP/DoVxwIhALBXeP+iKcmhYi3MWitB4cFi4V00SwZcnYWHOstjk79I"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"BVuAaur3Xs+g8R3ANU+0sMRLGgjzQeFkx8C/9DNR8uERB4v0BSjA8AKv4QlFrl3mYi+v24AL1J+zzpyEKPkaVW0PfZMMLkJkPD/uHAhloJ/UZdR1h1DG/ykFBzuYP/GhIKM2Rf7d+uIL1s4CvNcUw0/c4TxOD7b1hAHSa3aKfOSumDBdKbeKu9tUcewE/8qZB4B2JOb5S0AeZAGsGniavX8cI9xk3oBC6hTO5Ib7DEEMsDGKVZtAUkOKc4eA43LM1KMIuO8cXeSSv3jzR3/6SRizZfDDv2v+sUoFOgYrI+ECTaFLk+K+GDwh2vx04O1FW/ZU1V+o6TGAQ6F3oH1fzpgpBCsm5UP3Aad4zYx3/jiLsZM/R/UlUJ5LyPxeouM0wsTECMsi+jSVwucijSLzBBQaFuGogzcYUuxYYs1yzHBpLv+JDJ+UZTEfZZU1q34YQXh4Di38fnz14XWbJhinpwYjG4olq0q2bsD3L2wIed8YaCa+6I21KlLA2Q\\u003d\\u003d\",\"ephemeralPublicKey\":\"BBYBQi7gvlAAKnTignyLYokMe1Lyd5kaKi30U1onr29LQrgFrTwLLLJhBp5ktKLDBZDcqQ/PE21kU/W1C4pcfiI\\u003d\",\"tag\":\"BOb0TD38qT3eU1FT7mA/T6Hn0YAxhmyj3pO7qPW1PPU\\u003d\"}"}'
        // );
        // $original_token =  $simulated_tokenizationData['token'];
        // echo 'original token:  '.$original_token.PHP_EOL.PHP_EOL;
        // $token = json_decode($original_token,true); //json_decode without true return array
        $execDir = config('api.googlepay.exec_dir');    //for production dynamic setting configuration
        $execDir = rtrim($execDir, '/'). DIRECTORY_SEPARATOR;
        $certDir = config('api.googlepay.cert_dir');    //for production dynamic setting configuration
        
        $hardcode_public_key_addr = '/home/wliu/mwarrior2.0/api/certs/googlepay/'. 'TEST_KEY_PUB.pem';
        $hardcode_private_key_addr = '/home/wliu/mwarrior2.0/api/certs/googlepay/'. 'TEST_KEY.pem';
        $hardcode_private_key_addr_standard = '/home/wliu/mwarrior2.0/api/certs/googlepay/'. 'key.pem';
        $GooglePaymentMessagefile = file_get_contents('/home/wliu/signtest/paymentData.txt', true);
        $public_key_testing = file_get_contents($hardcode_public_key_addr);
        $MW_private_key_testing_addr_command = app_path(). '/'.$certDir. 'TEST_KEY.pem';  //execute in command line
        $MW_private_key_testing_addr_php = '/home/wliu/mwarrior2.0/api/certs/googlepay/'. 'TEST_KEY.pem';  //Eeecute in php
        $openssl_private_key_resource = openssl_pkey_get_private('file://'.$MW_private_key_testing_addr_php);//     'file://' for openssl
        if ($openssl_private_key_resource == false) {
            echo $MW_private_key_testing_addr_php.PHP_EOL;
            echo "Private Key resoruce can not be captured".PHP_EOL;
        } else {
            echo "Private Key resoruce has been captured successfully".PHP_EOL;
        }

        $GooglePaymentMessage = json_decode($GooglePaymentMessagefile);

        $token = json_decode($GooglePaymentMessage->googlePayData->paymentMethodData->tokenizationData->token);
  
            
            $signedMessage_decode = \GuzzleHttp\json_decode($token->signedMessage);
            // var_dump($signedMessage_decode);
            $encryptedMessage = $signedMessage_decode->encryptedMessage;  // most hindrance part for decrypting the message
            $mac_tag = $signedMessage_decode->tag;

            //TO DO List for decrypting captured Google Payment Token Message

            //1. Fetch the Google root signing keys.
            
            $Google_Root_Signing_keys_testing= file_get_contents('/home/wliu/mwarrior2.0/api/certs/googlepay/'. 'google_root_signing_key_test.txt');    //testing
            // $Google_Root_Signing_keys_production = file_get_contents(app_path(). '/'.$certDir. 'google_root_signing_key_production.txt');    //production
            // echo "Google Root Signing Key: ". $Google_Root_Signing_keys_testing.PHP_EOL;
            $Google_Root_Signing_keys_testing = json_decode($Google_Root_Signing_keys_testing,true);
 
            $google_root_signing_nonexpired_key_list = [];
            foreach($Google_Root_Signing_keys_testing['keys'] as  $keyinfo){
                //TODO determine whether it has been expired in production and teest key later
                // var_dump($keyinfo);
                array_push($google_root_signing_nonexpired_key_list,$keyinfo['keyValue']);

            }
            // var_dump($google_root_signing_nonexpired_key_list);
            //2. Verify that the signature of the intermediate signing key is valid by any of the non-expired root signing keys.
                //a. Find all non-expired root signing key

                //b. Verify the signature of the intermediate signning key
                $intermediate_verification_sender_id='Google';
                $intermediate_verification_protocol_version=$token->protocolVersion;
                $intermediate_verification_signed_key=json_encode($token->intermediateSigningKey->signedKey) ;
            
            $signedStringForIntermediateSigningKeySignature = pack('V',strlen($intermediate_verification_sender_id)).
                                                            $intermediate_verification_sender_id.
                                                            pack('V',strlen($intermediate_verification_protocol_version)).
                                                            $intermediate_verification_protocol_version.
                                                            pack('V',strlen($intermediate_verification_signed_key)).
                                                            $intermediate_verification_signed_key;

            // $public_key_testing_ID = openssl_pkey_get_public($public_key_testing);
            $public_key_testing = $public_key_testing;
            // echo $public_key_testing.PHP_EOL;

            // $public_key_testing= "-----BEGIN PUBLIC KEY-----\n" . wordwrap($public_key_testing, 64, "\n", true) . "\n-----END PUBLIC KEY-----";

            //below it is phpecc wrapping function, it should be working
        $public_key_content  = '-----BEGIN PUBLIC KEY-----'.PHP_EOL;
        $public_key_content .= trim(chunk_split(base64_encode($public_key_testing), 64, PHP_EOL)).PHP_EOL;
        $public_key_content .= '-----END PUBLIC KEY-----';



            //TODO verify all signatures in the list as $token->intermediateSigningKey->signatures[?]

            //3. Verify that the intermediate signing key of the payload hasn't expired.
                

            //4. Verify that the signature of the payload is valid by the intermediate signing key.
            
            
            //5. Decrypt the contents of the payload after you verify the signature. (Most hindrence)

                //a. generating sharedkey using ECIES-KEM as curve cryption only used in php version > 7, we use command instead of it
                    //a-1. Elliptic curve: NIST P-256, also known in OpenSSL as prime256v1.
                        //openssl define SN_X9_62_prime256v1             "prime256v1"
                        //openssl define NID_X9_62_prime256v1            415
                        //openssl define OBJ_X9_62_prime256v1            OBJ_X9_62_primeCurve,7L
                    //a-2. CheckMode, OldCofactorMode, SingleHashMode, and CofactorMode are 0.
                    //a-3. Encoding function: Uncompressed point format.
                    //a-4. Key derivation function: HKDFwithSHA256, as dejscribed in RFC 5869, with the following parameter:
                        //4.1 Salt must not be provided. Per the RFC, this must be equivalent to a salt of 32 zeroed bytes.


            $Google_ephemeralPublicKey = $signedMessage_decode->ephemeralPublicKey;


            // $formattedEphemeralPublicKey = $x509->getPublicKey();
            

            // $formattedEphemeralPublicKey_under_der2pem = der2pem_format($Google_ephemeralPublicKey);

            // $pemFormattedPublicKey = '-----BEGIN PUBLIC KEY-----' . PHP_EOL . chunk_split(base64_encode($leafPublicKey), 64, PHP_EOL) . '-----END PUBLIC KEY-----';
                
            $fileNameEphemeralPublicKey = "ephemeralPublicKey"."key".uniqid();
            $fullPathEphemeralPublicKey = $execDir. $fileNameEphemeralPublicKey;

            // Check if the ephemeral key path already exists. This would prevent uniqid being cycled.
            if(file_exists($fullPathEphemeralPublicKey)) return false; //later we should 1. operate or 2. return some response insteaded

            // $ciphertext =  $encryptedMessage;

            // $decrypted = $this->encrypter->decrypt($ciphertext, 'Google');
 // requires private_key1.pem to decrypt
            // $public_key = $public_key_testing_ID;
            $public_key = null;
            $private_key = file_get_contents($hardcode_private_key_addr);
            // $private_key = file_get_contents($hardcode_private_key_addr_standard);
            // var_dump($private_key);


            // $decrypted = $this->encrypter->decrypt($this->ciphertext);
            // $payload = \GuzzleHttp\json_decode($payload, JSON_OBJECT_AS_ARRAY);

            // var_dump($C0);

            // $generator = EccFactory::getNistCurves()->generator256();
         $generator = EccFactory::getSecgCurves()->generator256r1();

        //1. receive all needed resource for decryption -1. ephemeral_publick_key; -2. private_key -3. encrypted_message 
        $public_key_formatted = $public_key_content; // set it if we would like to hack Google encryption
        $public_key_origin = $public_key_testing; 
         
        $public_key_formatted = null;
         //2. Generating shared Key
         //3. HASH_HMAC_KDF_SHA256 GENERATING 512 BIT SYMETRIC KEY and split for symmetrical Key 256 + MAC_Verify_Key 256  
        
        //  echo "testingtestingtesting2:::".PHP_EOL;
        //handling uncompressed point into compressed point
        //ambiguous in expression even for the rfc-pdf it says it is the same???? but expression in php using hex and octs same value, so ambigous
        

        $ephemeral_public_key =  $Google_ephemeralPublicKey;
        $adapter = EccFactory::getAdapter();

        // $pemPub = new PemPublicKeySerializer(new DerPublicKeySerializer());
        $uncompressed_point_serializer = new UncompressedPointSerializer($adapter);
        $compressed_point_serializer = new CompressedPointSerializer($adapter);
        $uncompressed_point = $uncompressed_point_serializer->unserialize($generator->getCurve(), bin2hex(base64_decode($ephemeral_public_key )));
        $compressed_ephemeral_publickey = $compressed_point_serializer->serialize($uncompressed_point);

        // $compressed_publickey_point = $compressed_point_serializer->serialize($uncompressed_point);
        // echo "testingtesting001tesingtesing001".PHP_EOL.PHP_EOL;
        // $public_key_testin_content =  $pemPub->serialize($public_key_testing);

        $ECIESEManager = new ECIESManagerGooglePay(null, $private_key,'json');
 
         $ciphertext = base64_decode($encryptedMessage);
         $mac = base64_decode($mac_tag);
         $hardcode_label_info =  iconv("UTF-8", "ASCII", 'Google');
         //32 Bytes zero for IV
         $google_hkdf_iv = \hex2bin('00000000000000000000000000000000');


        //  $ECIESEManager->reconstructSharedSecret($C0_comppressed);
        echo "testingtesating001".
        $ECIESEManager->reconstructSharedSecret(bin2hex(base64_decode($ephemeral_public_key)));

        $decrypted = $ECIESEManager->decryptSymmetric($google_hkdf_iv, $ciphertext, $mac, '$hardcode_label_info');
        echo "TESTINGTESTING001".PHP_EOL.PHP_EOL;

            // mail("weilun@merchantwarrior.com","Debug - TestGooglePay - new", print_r("  decrypted text is: ".PHP_EOL.$decrypted));
        echo $decrypted.PHP_EOL.PHP_EOL;
        var_dump($decrypted);
            echo base64_encode($decrypted).PHP_EOL.PHP_EOL;
            echo base64_decode($decrypted).PHP_EOL.PHP_EOL;
            echo $decrypted.PHP_EOL.PHP_EOL;
            echo utf8_encode($decrypted).PHP_EOL.PHP_EOL;
            echo utf8_decode($decrypted).PHP_EOL.PHP_EOL;
            echo base64_encode($decrypted).PHP_EOL.PHP_EOL;
            echo "testingtesting base64".PHP_EOL;
            echo base64_decode($decrypted).PHP_EOL.PHP_EOL;
            echo bin2hex($decrypted).PHP_EOL.PHP_EOL;
            echo $decrypted.PHP_EOL.PHP_EOL;
            echo json_encode(utf8_encode($decrypted)).PHP_EOL.PHP_EOL;
            echo json_encode(utf8_decode($decrypted)).PHP_EOL.PHP_EOL;
            echo json_encode(base64_encode($decrypted)).PHP_EOL.PHP_EOL;
            echo "testingtesting jsonecoded base64".PHP_EOL;
            echo json_encode(base64_decode($decrypted)).PHP_EOL.PHP_EOL;
            echo json_encode(bin2hex($decrypted)).PHP_EOL.PHP_EOL;


            // VERSION 2.0 USING COMMANDLINE BUILDING EPHEMERAL PUBLIC KEY

            // $FormattedPublicKey = '-----BEGIN PUBLIC KEY-----' . PHP_EOL . chunk_split($C0_comppressed_public_key, 64, PHP_EOL) . '-----END PUBLIC KEY-----';
            // file_put_contents($fullPathEphemeralPublicKey,$FormattedPublicKey);
        
            // // echo $ephemeralPublicKey.PHP_EOL.PHP_EOL;
            // // $symmetricEncryptionKey = hash_hkdf("SHA256",base64_decode($MW_private_key_testing),32,"symmetricEncryptionKey",SELF::NON_SALT);

            // $FormattedPublicKey = generate_sharedKey();
            // file_put_contents($fullPathEphemeralPublicKey,$FormattedPublicKey);
            // // GENERATE Diffe Hellmen
            // $command = "cd $execDir && openssl pkeyutl -derive -inkey $MW_private_key_testing_addr_command -peerkey $fileNameEphemeralPublicKey";
            // // $pemFormattedPublicKey = '-----BEGIN PUBLIC KEY-----' . PHP_EOL . chunk_split(base64_encode($leafPublicKey), 64, PHP_EOL) . '-----END PUBLIC KEY-----';
            // echo $command. PHP_EOL;
            // $dh_shared_key = exec($command);

            // $kdf_symmetric_key = substr($ECIESEManager->KDF($dh_shared_key), 0, 32);;
            // echo $command. PHP_EOL;
            // $decrypted = $ECIESEManager->decryptSymmetric_symmetric($google_hkdf_iv, $ciphertext, $mac, $hardcode_label_info, $kdf_symmetric_key);


            // echo $decrypted;


            // mail("weilun@merchantwarrior.com","Debug - TestGooglePay - new", print_r("  decrypted text is: ".PHP_EOL.$decrypted));
            // var_dump(unpack("c2chars", $decrypted));
            // var_dump($decrypted);
            // echo base64_encode($decrypted).PHP_EOL.PHP_EOL;
            // echo base64_decode($decrypted).PHP_EOL.PHP_EOL;
            // echo $decrypted.PHP_EOL.PHP_EOL;
            // echo utf8_encode($decrypted).PHP_EOL.PHP_EOL;
            // echo utf8_decode($decrypted).PHP_EOL.PHP_EOL;
            // echo base64_encode($decrypted).PHP_EOL.PHP_EOL;
            // echo "testingtesting base64".PHP_EOL;
            // echo base64_decode($decrypted).PHP_EOL.PHP_EOL;
            // echo bin2hex($decrypted).PHP_EOL.PHP_EOL;
            // echo $decrypted.PHP_EOL.PHP_EOL;
            // echo json_encode(utf8_encode($decrypted)).PHP_EOL.PHP_EOL;
            // echo json_encode(utf8_decode($decrypted)).PHP_EOL.PHP_EOL;
            // echo json_encode(base64_encode($decrypted)).PHP_EOL.PHP_EOL;
            // echo "testingtesting jsonecoded base64".PHP_EOL;
            // echo json_encode(base64_decode($decrypted)).PHP_EOL.PHP_EOL;
            // echo json_encode(bin2hex($decrypted)).PHP_EOL.PHP_EOL;


            //VERSION 3.0 REBUILD THE WHOLE MECHANISM INCLUDING ENCRYPTION AND DECRYPTION
            // $public_key_testin_content =  $pemPub->serialize($public_key_testing);
            // $public_key_testing = new PublicKey($adapter, $generator, $uncompressed_point);
            // $ECIESEManager = new ECIESManagerGooglePay($public_key_testin_content, $private_key,'json');


            // // $dh_shared_key = bin2hex($dh_shared_key);

            // echo "openssl_private_key_resource:   ".$openssl_private_key_resource.PHP_EOL;

            // $dh_shared_key = openssl_dh_compute_key ($Google_ephemeralPublicKey_origin ,  $openssl_private_key_resource) ; //this function is non-ec dh

            // if ($dh_shared_key == false) {
            //     // echo $dh_shared_key.PHP_EOL;
            //     echo "dh shared Key resoruce can not be captured".PHP_EOL;
            //     echo openssl_error_string();
            // } else {
            //     echo "dh shared Key resoruce has been captured successfully".PHP_EOL;
            //     var_dump($dh_shared_key);
            // }

            // $kdfInfo = 'Google';
            // echo $kdfInfo.PHP_EOL;

            // $sharedSecret = hash_hkdf("sha256", $dh_shared_key, 64, $kdfInfo, self::NON_SALT); //php supported hkdf encryption algorithm

            // echo  "initilized sharedSecret: ".$sharedSecret.PHP_EOL;

            // // var_dump($sharedSecret);
            // $sharedSecret_splitted = str_split($sharedSecret, 32);
            // // print_r($sharedSecret_splitted);
            
            // $symmetricEncryptionKey = $sharedSecret_splitted[0];
            // // sharedSecret_splitted[1];


            //     //b. split the generated key two 256-bit-long keys: symmetricEncryptionKey and macKey
            // // echo "symmetricEncryptionKey:  ".$symmetricEncryptionKey.PHP_EOL;

            // // echo "macKey:  ".$macKey.PHP_EOL;
            // // echo "symmetricEncryptionKey based encode:  ".base64_encode($symmetricEncryptionKey).PHP_EOL;
            // // echo "macKey based encode:  ".base64_encode($macKey).PHP_EOL;
            //     //c. verify tag is valid MAC (HMAC-SHA256)

            // // $expected_MAC = hash_hmac("SHA256",$signedMessage_decode->tag,$macKey);
            // // echo "expercted_mac:   ".$expected_MAC.PHP_EOL;
            // // echo "encryptedMessage:   ".$encryptedMessage.PHP_EOL;

            //     // $ok = hash_equals($expected_MAC, $encryptedMessage);
            //     // echo "ok or not: ".$ok.PHP_EOL;
            //     // if ($ok == 1) {
            //     //     echo "encryptedMessage verify is GOOD".PHP_EOL;
            //     // } elseif ($ok == 0) {
            //     //     echo "encryptedMessage verify is bad".PHP_EOL;
            //     // } else {
            //     //     echo "encryptedMessage verify is ugly, error PLEASE checking signature".PHP_EOL;
            //     // }
            //     //d. Finally decrypte the encryptedMessage

            // //initializing command execution environment/directory   for using ECIES-KEM 

            // // var_dump(openssl_get_cipher_methods());
            // $this->decryptPaymentToken($encryptedMessage, $symmetricEncryptionKey);
            // echo "Originial encryptedMessage: ".$encryptedMessage.PHP_EOL.PHP_EOL;


            echo "Finishing Step 5".PHP_EOL.PHP_EOL;

            // $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-256-CTR'));// for example you algorithm = 'AES-256-CTR'
            // $decodedText =  base64_encode(openssl_decrypt($encryptedMessage,"AES-256-CTR",@hex2bin($symmetricEncryptionKey),OPENSSL_ZERO_PADDING,$iv));
            // echo "decodedText: ".$decodedText.PHP_EOL.PHP_EOL;

            
            //6. Verify that the message isn't expired. This requires you to check that the current time is less than the messageExpiration field in the decrypted contents.
           
           

           
            //7. Verify that the gatewayMerchantId matches the ID of the merchant that gave you the payload.




            //8. Use the payment method in the decrypted contents and charge it.



    }
}

/**
 * we are currently using the dem 2 mode so the "k" should start at 0
 * 
 * ISC License (ISC)
 *
 * Copyright (c) 2017, Andrey Andreev <narf@devilix.net>
 * All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * hash_hkdf() compat package
 *
 * A userland implementation of hash_hkdf() for PHP versions prior to 7.1.2.
 *
 * @package	hash_hkdf_compat
 * @author	Andrey Andreev <narf@devilix.net>
 * @copyright	Copyright (c) 2017, Andrey Andreev <narf@devilix.net>
 * @license	http://opensource.org/licenses/ISC ISC License (ISC)
 * @link	https://github.com/narfbg/hash_hkdf_compat
 */
if ( ! function_exists('hash_hkdf'))
{
	/**
	 * hash_hkdf()
	 *
	 * An RFC5869-compliant HMAC Key Derivation Function implementation.
	 *
	 * @link	https://secure.php.net/hash_hkdf
	 * @link	https://tools.ietf.org/rfc/rfc5869.txt
	 *
	 * @param	string	$algo   Hashing algorithm
	 * @param	string  $ikm	Input keying material
	 * @param	int	$length	Desired output length
	 * @param	string	$info	Context/application-specific info
	 * @param	string	$salt	Salt
	 * @return	string
	 */
	function hash_hkdf($algo = null, $ikm = null, $length = 0, $info = '', $salt = '')
	{
		// To match PHP's behavior as closely as possible (unusual
		// inputs and error messages included), we'll have to do
		// some weird stuff here ...
		if (func_num_args() < 2)
		{
			trigger_error(
				sprintf("hash_hkdf() expects at least 2 parameters, %d given", func_num_args()),
				E_USER_WARNING
			);
			return null;
		}
		elseif (func_num_args() > 5)
		{
			trigger_error(
				sprintf("hash_hkdf() expects at most 5 parameters, %d given", func_num_args()),
				E_USER_WARNING
			);
			return null;
		}

		foreach (array(1 => 'algo', 2 => 'ikm', 4 => 'info', 5 => 'salt') as $paramNumber => $paramName)
		{
			switch ($paramType = gettype($$paramName))
			{
				case 'string': break;
				case 'integer':
				case 'double':
				case 'NULL':
					$$paramName = (string) $$paramName;
					break;
				case 'boolean':
					// Strangely, every scalar value BUT bool(true)
					// can be safely casted ...
					$$paramName = ($$paramName === true) ? '1' : '';
					break;
				case 'object':
					if (is_callable(array($$paramName, '__toString')))
					{
						$$paramName = (string) $$paramName;
						break;
					}
				default:
					trigger_error(
						sprintf("hash_hkdf() expects parameter %d to be string, %s given", $paramNumber, $paramType),
						E_USER_WARNING
					);
					return null;
			}
		}

		static $sizes;
		if ( ! isset($sizes))
		{
			// Non-cryptographic hash functions are blacklisted,
			// so we might as well flip that to a whitelist and
			// include all the digest sizes here instead of
			// doing strlen(hash($algo, '')) on the fly ...
			//
			// Find the interesection of what's available on
			// PHP 7.1 and whatever version we're using.
			$sizes = array_intersect_key(
				array(
					'md2'         => 16, 'md4'         => 16, 'md5'         => 16,
					'sha1'        => 20,
					'sha224'      => 28, 'sha256'      => 32, 'sha384'      => 48,
					'sha512/224'  => 28, 'sha512/256'  => 32, 'sha512'      => 64,
					'sha3-224'    => 28, 'sha3-256'    => 32, 'sha3-384'    => 48, 'sha3-512'    => 64,
					'ripemd128'   => 16, 'ripemd160'   => 20, 'ripemd256'   => 32, 'ripemd320'   => 40,
					'whirlpool'   => 64,
					'tiger128,3'  => 16, 'tiger160,3'  => 20, 'tiger192,3'  => 24,
					'tiger128,4'  => 16, 'tiger160,4'  => 20, 'tiger192,4'  => 24,
					'snefru'      => 32, 'snefru256'   => 32,
					'gost'        => 32, 'gost-crypto' => 32,
					'haval128,3'  => 16, 'haval160,3'  => 20, 'haval192,3'  => 24, 'haval224,3'  => 28, 'haval256,3'  => 32,
					'haval128,4'  => 16, 'haval160,4'  => 20, 'haval192,4'  => 24, 'haval224,4'  => 28, 'haval256,4'  => 32,
					'haval128,5'  => 16, 'haval160,5'  => 20, 'haval192,5'  => 24, 'haval224,5'  => 28, 'haval256,5'  => 32,
				),
				array_flip(hash_algos())
			);

			// PHP pre-5.4.0's output for Tiger hashes is in little-endian byte order - blacklist
			if ( ! defined('PHP_VERSION_ID') || PHP_VERSION_ID < 50400)
			{
				unset(
					$sizes['tiger128,3'], $sizes['tiger160,3'], $sizes['tiger192,3'],
					$sizes['tiger128,4'], $sizes['tiger160,4'], $sizes['tiger192,4']
				);
			}
		}

		if ( ! isset($sizes[$algo]))
		{
			// Edge case ...
			// PHP does case-insensitive lookups and 'Md5', 'sHa1', etc. are accepted.
			// Still, we want to preserve the original input for the error message.
			if ( ! isset($sizes[strtolower($algo)]))
			{
				if (in_array(strtolower($algo), hash_algos(), true) && strncasecmp($algo, 'tiger1', 6) !== 0)
				{
					trigger_error("hash_hkdf(): Non-cryptographic hashing algorithm: {$algo}", E_USER_WARNING);
					return false;
				}

				trigger_error("hash_hkdf(): Unknown hashing algorithm: {$algo}", E_USER_WARNING);
				return false;
			}

			$algo = strtolower($algo);
		}

		if ( ! isset($ikm[0]))
		{
			trigger_error("hash_hkdf(): Input keying material cannot be empty", E_USER_WARNING);
			return false;
		}

		if ( ! is_int($length))
		{
			// Integer casting rules so bizzare that we can't even cover all of them.
			// We'll try for just the simpler cases ...
			if (is_string($length) && isset($length[0]) && strspn($length, "0123456789", $length[0] === '-' ? 1 : 0))
			{
				$length = (int) $length;
			}
			// For some reason, this next line executes without being marked as covered
			elseif (is_float($length)) // @codeCoverageIgnore
			{
				$length = (int) ($length < 0 ? ceil($length) : floor($length));
			}
			elseif ( ! isset($length) || is_bool($length))
			{
				$length = (int) $length;
			}
			else
			{
				trigger_error(
					sprintf("hash_hkdf() expects parameter 3 to be integer, %s given", gettype($length)),
					E_USER_WARNING
				);
				return null;
			}
		}

		if ($length < 0)
		{
			trigger_error("hash_hkdf(): Length must be greater than or equal to 0: {$length}", E_USER_WARNING);
			return false;
		}
		elseif ($length > (255 * $sizes[$algo]))
		{
			trigger_error(
				sprintf("hash_hkdf(): Length must be less than or equal to %d: %d", 255 * $sizes[$algo], $length),
				E_USER_WARNING
			);
			return false;
		}
		elseif ($length === 0)
		{
			$length = $sizes[$algo];
		}

		isset($salt[0]) || $salt = str_repeat("\x0", $sizes[$algo]);
		$prk = hash_hmac($algo, $ikm, $salt, true);
		$okm = '';
		for ($keyBlock = '', $blockIndex = 1; ! isset($okm[$length - 1]); $blockIndex++)
		{
			$keyBlock = hash_hmac($algo, $keyBlock.$info.chr($blockIndex), $prk, true);
			$okm .= $keyBlock;
		}

		// Byte-safety ...
		return defined('MB_OVERLOAD_STRING')
			? mb_substr($okm, 0, $length, '8bit')
			: substr($okm, 0, $length);
	}
}



function generate_sharedKey(){

    $GooglePaymentMessagefile = file_get_contents('/home/wliu/signtest/paymentData.txt', true);
    $hardcode_private_key_addr = '/home/wliu/mwarrior2.0/api/certs/googlepay/'. 'TEST_KEY.pem';
    $GooglePaymentMessage = json_decode($GooglePaymentMessagefile);
    $token = json_decode($GooglePaymentMessage->googlePayData->paymentMethodData->tokenizationData->token);
    $signedMessage_decode = \GuzzleHttp\json_decode($token->signedMessage);
    // $encryptedMessage = $signedMessage_decode->encryptedMessage;
    $Google_ephemeralPublicKey = $signedMessage_decode->ephemeralPublicKey;

    $formattedEphemeralPublicKey = '-----BEGIN PUBLIC KEY-----'. PHP_EOL;
    $formattedEphemeralPublicKey .= chunk_split($Google_ephemeralPublicKey, 64);
    $formattedEphemeralPublicKey .= '-----END PUBLIC KEY-----';

    $fileNameEphemeralPublicKey = "/home/wliu/mwarrior2.0/api/certs/googlepay/ephemeralPublicKey".uniqid();
    $fullPathEphemeralPublicKey =  $fileNameEphemeralPublicKey;
    if(file_exists($fullPathEphemeralPublicKey)) return false; //later we should 1. operate or 2. return some response insteaded
    file_put_contents($fullPathEphemeralPublicKey, $formattedEphemeralPublicKey);

    $adapter = EccFactory::getAdapter();
    // $generator = EccFactory::getNistCurves()->generator256();
    $generator = EccFactory::getSecgCurves()->generator256r1();
    $useDerandomizedSignatures = true;

    $pemPub = new PemPublicKeySerializer(new DerPublicKeySerializer());
    $pemPriv = new PemPrivateKeySerializer(new DerPrivateKeySerializer());

    # These .pem and .key are for different keys
    $alice_content = file_get_contents($hardcode_private_key_addr);
    $bob_content = file_get_contents($fullPathEphemeralPublicKey);

    $alicePriv = $pemPriv->parse($alice_content);
    // var_dump($alicePriv);
    // $bobPub = $pemPub->parse($pemPub->serialize($bob_content));
    $uncompressed_point_serializer = new UnCompressedPointSerializer($adapter);
    $uncompressed_point = $uncompressed_point_serializer->unserialize($generator->getCurve(), bin2hex(base64_decode($Google_ephemeralPublicKey)));
    $bobPub = new PublicKey($adapter, $generator, $uncompressed_point);
    // echo "testingtesting001tesingtesing001".PHP_EOL.PHP_EOL;
    $pemPub->serialize($bobPub);
    // var_dump($uncompressed_point);

    // $exchange = $alicePriv->createExchange($bobPub);
    // $shared = $exchange->calculateSharedKey();
    // var_dump($shared);

    // return gmp_strval($shared, 10);
    return $pemPub->serialize($bobPub); ;

}



/*
 *
 * Partial implementation of ECIES key encapsulation (ElGamal)
 * ISO 18033-2 10.2
 * http://www.shoup.net/iso/std6.pdf
 *
 * No OldCofactorMode, CofactorMode or CheckMode currently supported
 *
 */

class ECIESManagerGooglePay
{
    protected $public_key;
    protected $private_key;
    protected $single_hash_mode = 0; // should be false in the GooglePayCase
    protected $prime_length;
    protected $adapter;
    protected $compressed_point_serializer;
    protected $random_number_generator;

    protected $CofactorMode = 0;    // only for decryption
    protected $OldCofactorMode = 0;  //only for decryption
    protected $CheckMode = 0; //only for decryption

    /**
     * The ephemeral public point
     *
     * @var Point
     */
    protected $gTilde;

    /**
     * The point of the ephemeral shared secret
     *
     * @var Point
     */
    protected $hTilde;

    /**
     * The octet string serialization of the ephemeral shared secret (without leading point-format byte)
     *
     * @var string
     */
    protected $PEH;

    /**
     * The generator point for the chosen curve
     *
     * @var Point
     */
    protected $generator_point;


    /**
     * The the serialized compressed ephemeral public point. Raw byte string, not hex.
     *
     * @var string
     */
    protected $ephemeral_public_point_serialized;


    /**
     * The symmetric encryption key derived from the ephemeral shared secret
     *
     * @var string
     */
    protected $derived_symmetric_key;

    /**
     * The symmetric MAC key derived from the ephemeral shared secret
     *
     * @var string
     */
    protected $derived_mac_key;

    /**
     * Either 'iso18033-2' or 'json'.
     * 'iso18033-2' should be compatible with other implementations of ECIES
     *
     * @var string
     */
    protected $output_structure;

    /**
     * Either 1 or 2.
     * Determines whether to implement KDF1 or KDF2 from ISO-18033-2
     * GoolePay is based on kdf 1
     * @var int
     */
    protected $kdf_one_or_two = 1;

    /**
     * The length of the KDF generated hash (in bytes). Must ensure there are enough bytes for
     * both the chosen symmetric cipher and MAC key (in our case, 256 bits for each)
     *
     * @var int
     */
    protected $desired_hash_length = 64;

    /**
     * Must be a valid hashing algorithm
     *
     * @var string
     */
    protected $hash_algorithm = 'sha256';

    const PERMITTED_CURVES = [
        'secp112r1',
        'secp256k1',
        'secp256r1',
        'secp384r1',
        'nistp192',
        'nistp224',
        'nistp256',
        'nistp384',
        'nistp521'
    ];

    const ISO_FORMAT = 'iso18033-2';

    const JSON_FORMAT = 'json';

    /**
     * Create a new ECIESEncrypter instance.
     *
     * @param  string  $public_key
     * @param  string  $private_key
     * @param  string  $output_structure
     *
     * @throws \RuntimeException
     */

    public function __construct($public_key, $private_key, $output_structure = null)
    {
        if(is_null($public_key) && is_null($private_key)){
            throw new RuntimeException('Either public key or private key must be set in env(\'ECC_PUBLIC_KEY_PATH\') and env(\'ECC_PRIVATE_KEY_PATH\'). Could not locate either key');
        }

        if($output_structure != self::ISO_FORMAT && $output_structure != self::JSON_FORMAT){
            throw new RuntimeException('Output structure must be either "' . self::ISO_FORMAT . '" or "' . self::JSON_FORMAT . '"');
        }

        $this->output_structure = $output_structure;

        $pemPrivateKeySerializer = new PemPrivateKeySerializer(new DerPrivateKeySerializer());
        $pemPublicKeySerializer = new PemPublicKeySerializer(new DerPublicKeySerializer());


        if(!is_null($public_key)){
            $this->public_key = $pemPublicKeySerializer->parse($public_key);
            $curve = $this->public_key->getCurve();
        }

        if(!is_null($private_key)){
            $this->private_key = $pemPrivateKeySerializer->parse($private_key);
            $curve = $this->private_key->getCurve();
        }

        if(!is_null($curve) && !in_array($curve->getName(), self::PERMITTED_CURVES)){
            throw new RuntimeException('The only supported curves are secp112r1, secp256k1, secp256r1, secp384r1, nistp192, nistp224, nistp256, nistp384 and nistp521.');
        }

        $this->adapter = EccFactory::getAdapter();
        $this->compressed_point_serializer = new CompressedPointSerializer($this->adapter);
        $this->uncompressed_point_serializer = new UnCompressedPointSerializer($this->adapter);
        $this->setGeneratorForCurve($curve->getName());
        $this->random_number_generator = RandomGeneratorFactory::getRandomGenerator();
        $this->prime_length =  CurveOidMapper::getByteSize($this->generator_point->getCurve());
    }

    /**
     * Sets the correct generator point for the curve used in the public or private key
     *
     * @param  string  $curve
     */
    protected function setGeneratorForCurve($curve)
    {
        switch($curve){
            case 'secp112r1':
                $this->generator_point = EccFactory::getSecgCurves()->generator112r1();
                break;
            case 'secp256k1':
                $this->generator_point = EccFactory::getSecgCurves()->generator256k1();
                break;
            case 'secp256r1':
                $this->generator_point = EccFactory::getSecgCurves()->generator256r1();
                break;
            case 'secp384r1':
                $this->generator_point = EccFactory::getSecgCurves()->generator384r1();
                break;
            case 'nistp192':
                $this->generator_point = EccFactory::getNistCurves()->generator192();
                break;
            case 'nistp224':
                $this->generator_point = EccFactory::getNistCurves()->generator224();
                break;
            case 'nistp256':
                $this->generator_point = EccFactory::getNistCurves()->generator256();
                break;
            case 'nistp384':
                $this->generator_point = EccFactory::getNistCurves()->generator384();
                break;
            case 'nistp521':
                $this->generator_point = EccFactory::getNistCurves()->generator521();
                break;
            default:
                throw new RuntimeException('The only supported curves are secp112r1, secp256k1, secp256r1, secp384r1, nistp192, nistp224, nistp256, nistp384 and nistp521.');
        }
    }


    /**
     * This corresponds to ISO18033-2 - I2OSP(integer, octet_string_length)
     *
     * Converts 32-bit integer to BigEndian byte string
     * Primarily used for compatibility with Java BouncyCastle
     *
     * @param  int $i
     * @param int $length
     * @return string
     */
    public static function integerToOctetString($i, $length = 4)
    {
        if($i > PHP_INT_MAX){
            throw new RuntimeException("Integer larger than maximum allowed");
        }

        $length_in_bytes =  ceil(strlen(dechex($i)) / 2);

        if ($length_in_bytes > $length) {
            throw new RuntimeException("Integer cannot be stored in byte string of this length");
        }

        $length = $length * 2;
        return hex2bin(sprintf("%0".$length."X", $i));
    }

    /**
     * This corresponds to ISO18033-2 - HC.Encrypt(public_key, label, plaintext, options)
     *
     * @param $value
     * @param $label
     * @param $single_hash_mode
     *
     * @return string
     */
    public function encrypt($value, $label = '', $single_hash_mode = true)
    {
        $this->single_hash_mode = $single_hash_mode;

        // random integer between 1 and the order (mu), acts as ephemeral private key
        $r =  $this->random_number_generator->generate($this->generator_point->getOrder());

        $this->generateEphemeralKeys($r);

        $C0 = $this->ephemeral_public_point_serialized;
        $C1 =  $this->encryptSymmetric($value, $label);

        $payload = $C1;

        if($this->output_structure === self::ISO_FORMAT){
            return base64_encode($C0 . $C1);
        }
        else{
            $payload['ephemeral_public_point'] = $C0;

            foreach ($payload as $key => $value){
                $payload[$key] = base64_encode($value);
            }

            $payload['label'] = $label;

            $json = json_encode($payload);

            if (! is_string($json)) {
                throw new EncryptException('Could not encrypt the data.');
            }
            return $json;
        }
    }
    public function get_ephemeral_public_key_with_public(){
        $r =  $this->random_number_generator->generate($this->generator_point->getOrder());
        return $this->generateEphemeralKeys($r);
    }

    /**
     * This corresponds to ISO18033-2 - KEM.Encrypt(public_key, options)
     * No OldCofactorMode, CofactorMode or CheckMode currently supported 
     * Google Pay specification 4 parameters Corresponded with encryption 
     * @param \GMP $r
     * @return string
     */
    public function generateEphemeralKeys($r){
        if(is_null($this->public_key)){
            throw new EncryptException('Could not encrypt without the public key');
        }
        // If you're unfamiliar with ECIES, it might be helpful to think of ECIES 
        //as similar to Elliptic Curve Diffie-Hellman key exchange, 
        //only using an ephemeral private key ($r) to derive an ephemeral public point 
        //($gTilde), which is then sent with the ciphertext and used on the other side to reconstruct the shared secret.

        // $h is the permanent public point, which is the x (the permanent private key) times the generator
        // i.e. $h = $this->generator_point->mul($private_key)
        $h = $this->public_key->getPoint();


        // no OldCofactorMode at the moment, otherwise we'd multiply $r by nu (where nu = (the index of G in H) modulo mu)
        $rPrime = $r;

        // gTilde is the ephemeral public point. This means a new point which can be used to reconstruct $r
        // (iff you have the permanent private key)
        $this->gTilde = $this->generator_point->mul($r);

        /*
         hTilde is the point of the ephemeral shared secret.
         It can be calculated as either :
                  (permanent_private * generator) * ephemeral_private
          i.e.    (       permanent_public      ) * ephemeral_private   // when encrypting
            OR
                  (ephemeral_private * generator) * permanent_private
         i.e.     (       ephemeral_public      ) * permanent_private   // when decrypting
        */
        $this->hTilde = $h->mul($rPrime);

        return $this->deriveKeysFromEphemeralPoints();
    }

    /**
     * This corresponds to ISO18033-2 - DEM.Encrypt(symmetric_key, label, message)
     *
     * @param $value
     * @param $label
     *
     * @return string
     */
    protected function encryptSymmetric($value, $label){
        $iv = random_bytes(16); // 16 byte IV because block size is 128-bit, even with 256 bit key

        $ciphertext = \openssl_encrypt(igbinary_serialize($value), 'AES-256-CTR', $this->derived_symmetric_key, 0, $iv);

        if ($ciphertext === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        $ciphertext = base64_decode($ciphertext);

        $mac = hash_hmac('sha256', $iv . $ciphertext . $label . $this->integerToOctetString(8 * strlen($label), 8), $this->derived_mac_key, true);

        $C1 =  $iv . $ciphertext . $mac;

        if($this->output_structure === self::ISO_FORMAT){
            return $C1;
        }

        return compact('iv', 'ciphertext', 'mac');
    }

    /**
     * This corresponds to ISO18033-2 - HC.Decrypt(private_key, label, ciphertext)
     *
     * @param $payload - encrypted message can accepted in both iso18033-2 and 'json'
     * @param $label - contracted info
     * @param $single_hash_mode - 1 or 0
     *
     * @return string
     */
    public function decrypt($payload, $label = '', $single_hash_mode = true)
    {
        $this->single_hash_mode = $single_hash_mode;

        if($this->output_structure === self::ISO_FORMAT){
            $payload = base64_decode($payload);
            $C0 = substr($payload, 0, $this->prime_length + 1);
            $C1 = substr($payload, $this->prime_length + 1);

            if(strlen($C1) < strlen($this->derived_mac_key) + 16 + 16 ){ // IV length is 128-bits (16 bytes), minimum block is 128-bits, MAC key is whatever
                throw new DecryptException('Could not decrypt. Payload too short');
            }

            $iv = substr($C1, 0, 16);

            $ciphertext = substr($C1, 16, strlen($C1) - 32 - 16); // minus 32 bytes for mac_code, minus 16 for IV.

            $mac = substr($C1, -32); // last 32 bytes is SHA-256 MAC code

        }
        else{

            $payload = \GuzzleHttp\json_decode($payload, JSON_OBJECT_AS_ARRAY);

            $C0 = base64_decode($payload['ephemeral_public_point']);

            //Google Pay IV should be ''
            $iv = base64_decode($payload['iv']);

            $ciphertext = base64_decode($payload['ciphertext']);

            $mac = base64_decode($payload['mac']);

            $label = $payload['label'];

        }

        $this->reconstructSharedSecret($C0);

        $decrypted = $this->decryptSymmetric($iv, $ciphertext, $mac, $label);

        return igbinary_unserialize($decrypted);
    }


    /**
     * This corresponds to KEM.Decrypt(private_key, ephemeral_public_point)
     *
     * @param $C0
     * The ephemeral public point
     */
    public function reconstructSharedSecret($C0){
        if(is_null($this->private_key)){
            throw new DecryptException('Could not decrypt without the private key');
        }
        // $this->gTilde = $this->compressed_point_serializer->unserialize($this->generator_point->getCurve(), $C0);
        
        $this->gTilde = $this->uncompressed_point_serializer->unserialize($this->generator_point->getCurve(), $C0);

        $this->hTilde = $this->gTilde->mul($this->private_key->getSecret());

        if($this->hTilde->isInfinity()){
            throw new DecryptException('Ephemeral shared secret was infinity');
        }

        $this->deriveKeysFromEphemeralPoints();
    }


    /**
     * This derives the symmetric key and MAC key from the serialized ephemeral shared secret ($hTilde)
     *
     * @param PointInterface $hTilde
     * @param PointInterface $gTilde
     *
     * @return string
     */
    protected function deriveKeysFromEphemeralPoints()
    {

        // C0 is the octet string encoded version of the ephemeral public point (gTilde)
    // $C0 = hex2bin($this->compressed_point_serializer->serialize($this->gTilde));
        $C0 = hex2bin($this->uncompressed_point_serializer->serialize($this->gTilde));


        // PEH is the octet encoded shared secret point, used in the KDF to derive symmetric key
        // We remove the leading "point-format" byte because PEH is generated by the partial encoding function E'()
    // $this->PEH = ltrim(hex2bin($this->compressed_point_serializer->serialize($this->hTilde)), hex2bin($this->compressed_point_serializer->getPrefix($this->hTilde)));

        $this->PEH = ltrim(hex2bin($this->uncompressed_point_serializer->serialize($this->hTilde)), hex2bin('04'));



        if($this->single_hash_mode){

            $kdf_bytes = $this->KDF($this->PEH);
        }
        else{
            //Google Pay using single_hash_mode == 0
            $kdf_bytes = $this->KDF($C0.$this->PEH);
        }

        // 32 byte (256 bit) AES key derived from SHA-512 hash of shared secret point
        $kdf_symmetric_key = substr($kdf_bytes, 0, 32);
        // echo "testingtesting1:  ".$kdf_symmetric_key.PHP_EOL;
        // 32 byte (256 bit) HMAC key derived from SHA-512 hash of shared secret point
        $kdf_mac_key = substr($kdf_bytes, 32, 32);

        // echo "testingtesting2:  ".$kdf_mac_key.PHP_EOL;

        $this->ephemeral_public_point_serialized = $C0;
        $this->derived_symmetric_key = $kdf_symmetric_key;

        // echo "testingtesting001: ".$this->derived_symmetric_key.PHP_EOL.PHP_EOL;
        $this->derived_mac_key = $kdf_mac_key;

        return $kdf_bytes;
    }


    /**
     * Corresponds to ISO18033-2 - KDF(x, length), where length = 512 bits (64 bytes) and therefore k=1
     * Can be switched between KDF1 and KDF2
     *
     * @param string $input
     * @return string
     * @internal param $one_or_two
     * @internal param int $desired_hash_length
     * @internal param string $hash_algorithm
     */
    public function KDF($input)
    {
        $permitted_algorithms = hash_algos();

        if(!in_array($this->hash_algorithm, $permitted_algorithms)){
            throw new InvalidArgumentException("Hash algorithm '". $this->hash_algorithm . "' does not exist");
        }
        // $hardcode_label_info =  iconv("UTF-8", "ASCII", 'Google');

        $hardcode_label_info = 'Google';

        $salt = str_repeat("\x0", 32);
        //
        // $hash_length = strlen(hash($this->hash_algorithm, 'Google is ....', true));
        $HKDF_result = hash_hkdf($this->hash_algorithm, $input, 64, $hardcode_label_info, $salt);
        return $HKDF_result;

        // $k = ceil($this->desired_hash_length/$hash_length);
        // //AS hash alogorithm is sha256 the rounding should be 2
        // // echo "kdf k value:  ".$k;

        // if($this->kdf_one_or_two == 1){
        //     $start = 0;
        //     $end = $k - 1;
        // }
        // else{
        //     $start = 1;
        //     $end = $k;
        // }
        // $hardcode_label_info =  iconv("UTF-8", "ASCII", 'Google');
        // $kdf_bytes = '';

        // $salt = str_repeat("\x0", 32);

        // $prk = hash_hmac('sha256', $ikm, $salt, true);
        
        // //HMAC-Hash(PRK, T(0) | info | 0x01)
        // // T(0) = empty string (zero length)
        // //T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
        // // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
        // //T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)

        // for($i = $start; $i <= $end; $i++){
        //     $blockIndex = $i+1;
        //     $kdf_bytes .= hash_hmac($this->hash_algorithm, $input . $this->integerToOctetString($i, 4), true);
        // }
        // return substr($kdf_bytes, 0, $this->desired_hash_length);

    }




    /**
     * This corresponds to DEM.Decrypt(symmetric_key, label, ciphertext)
     *
     * @param $iv
     * @param $ciphertext
     * @param $mac
     * @param $label
     *
     * @return string
     */
    public function decryptSymmetric($iv, $ciphertext, $mac, $label)
    {
        $calculated_mac = hash_hmac('sha256', $iv . $ciphertext . $label . $this->integerToOctetString(8 * strlen($label), 8), $this->derived_mac_key, true);

        if(! hash_equals($calculated_mac, $mac)){
            // throw new DecryptException('The MAC is invalid.');
            echo "The MAC is invalid.".PHP_EOL.PHP_EOL;
        }

        $decrypted = \openssl_decrypt(base64_encode($ciphertext), 'AES-256-CTR', $this->derived_symmetric_key, 0, $iv);

        if ($decrypted == false) {
            throw new DecryptException('Could not decrypt the data.');
            echo "Could not decrypt the data.";
        }
        return $decrypted;
    }

    public function decryptSymmetric_symmetric($iv, $ciphertext, $mac, $label,$derived_symmetric_key)
    {
        $calculated_mac = hash_hmac('sha256', $iv . $ciphertext . $label . $this->integerToOctetString(8 * strlen($label), 8), $this->derived_mac_key, true);

        if(! hash_equals($calculated_mac, $mac)){
            // throw new DecryptException('The MAC is invalid.');
            echo "The MAC is invalid.".PHP_EOL.PHP_EOL;
        }

        $decrypted = \openssl_decrypt(base64_encode($ciphertext), 'AES-256-CTR', $derived_symmetric_key, 0, $iv);

        if ($decrypted == false) {
            throw new DecryptException('Could not decrypt the data.');
            echo "Could not decrypt the data.";
        }
        return $decrypted;
    }


}


function test_resource_version1(){
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
         $public_key = null; // set it if we would like to hack Google encryption
         $signed_message= json_decode($signed_message);
         $ephemeral_public_key = json_decode($signed_message->signedMessage)->ephemeralPublicKey;
         $private_key = $private_key_simulation;
         $encrypted_message = json_decode($signed_message->signedMessage)->encryptedMessage;
         $mac_tag =   json_decode($signed_message->signedMessage)->tag;
         //Testing all the needed message retrieve successful
         // echo $private_key.$ephemeral_public_key.$encrypted_message.PHP_EOL;
         
 
         
 
         //2. Generating shared Key
         //3. HASH_HMAC_KDF_SHA256 GENERATING 512 BIT SYMETRIC KEY and split for symmetrical Key 256 + MAC_Verify_Key 256  
         // $hardcode_label_info = ord('G')ord('o').ord('o').ord('g)'.ord('l').ord('e');
 
         $ECIESEManager = new ECIESManagerGooglePay($public_key, $private_key,'json');
         $C0 = base64_decode($ephemeral_public_key);
 
         $ciphertext = base64_decode($encrypted_message);
         $mac = base64_decode($mac_tag);
         $hardcode_label_info =  iconv("UTF-8", "ASCII", 'Google');
         $google_hkdf_iv = \hex2bin('00000000000000000000000000000000');
         
         $ECIESEManager->reconstructSharedSecret($C0);
         
         $decrypted_text = decryptSymmetric($google_hkdf_iv, $ciphertext, $mac, $hardcode_label_info);
         echo $decrypted_text;
}