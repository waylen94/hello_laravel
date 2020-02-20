<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

//dealing with asn1 format
use FG\ASN1\Universal\Sequence;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\BitString;


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

        
       $private_key_simulation = "";
       $public_key_simulation = "";

       $ephemeral_public_key_signedmessage_received = "";

       $standard_decrypted_message = "";



        echo "Beigining Testing ECC Algorithm".PHP_EOL.PHP_EOL;

        $ephemeralPublickey_uncompressed_raw = "BOdoXP+9Aq473SnGwg3JU1aiNpsd9vH2ognq4PtDtlLGa3Kj8TPf+jaQNPyDSkh3JUhiS0KyrrlWhAgNZKHYF2Y=";

        $ephemeral_point = $this->key_unserialize(bin2hex(base64_decode($ephemeralPublickey_uncompressed_raw)));

        var_dump( $ephemeral_point) ;

        $ephemeralPublickey_uncompressed = new PublicKey($ephemeral_point);

        $ephemeralPublicKey = $this->publickey_serialize($ephemeralPublickey_uncompressed);
        //resource version one
        $this->resource_version1();


        echo $ephemeralPublicKey.PHP_EOL.PHP_EOL;

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
    /**
     * @param string           $data
     * @return Point
     */
    public function key_unserialize(string $data): Point
    {
        if ($this->substring($data, 0, 2) != '04') {
            return false;
        }

        $data = $this->substring($data, 2);
        $dataLength = $this->length($data);

        $x = gmp_init($this->substring($data, 0, $dataLength / 2), 16);
        $y = gmp_init($this->substring($data, $dataLength / 2), 16);

        return new Point($x,$y);
    }

/**
     * Multi-byte-safe substring calculation
     *
     * @param string $str
     * @param int $start
     * @param int $length (optional)
     * @return string
     */
    public function substring(string $str, int $start = 0, int $length = null): string
    {
        // Premature optimization: cache the function_exists() result
        static $exists = null;
        if ($exists === null) {
            $exists = function_exists('mb_substr');
        }

        // If it exists, we need to make sure we're using 8bit mode
        if ($exists) {
            return mb_substr($str, $start, $length, '8bit');
        } elseif ($length !== null) {
            return substr($str, $start, $length);
        }
        return substr($str, $start);
    }
        /**
     * Multi-byte-safe string length calculation
     *
     * @param string $str
     * @return int
     */
    public function length(string $str): int
    {
        // Premature optimization: cache the function_exists() result
        static $exists = null;
        if ($exists === null) {
            $exists = function_exists('mb_strlen');
        }

        // If it exists, we need to make sure we're using 8bit mode
        if ($exists) {
            return mb_strlen($str, '8bit');
        }
        return strlen($str);
    }

    /**
     * specificied for uncompressed public key
     * {@inheritDoc}
     * @see \Mdanter\Ecc\Serializer\PublicKey\PublicKeySerializerInterface::serialize()
     */
    public function publickey_serialize(PublicKey $key): string
    {
        $publicKeyInfo = $this->format($key);

        $content  = '-----BEGIN PUBLIC KEY-----'.PHP_EOL;
        $content .= trim(chunk_split(base64_encode($publicKeyInfo), 64, PHP_EOL)).PHP_EOL;
        $content .= '-----END PUBLIC KEY-----';

        return $content;
    }
    //1.2.840.10045.2.1
    //ANSI X9.62 standard (1998) "Public Key Cryptography for the Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)"
   //1.2.840.10045.3.1.7
   //256-bit Elliptic Curve Cryptography (ECC), also known as National Institute of Standards and Technology (NIST) P-256

    public function format(PublicKey $key): string
    {
        $sequence = new Sequence(
            new Sequence(
                new ObjectIdentifier('1.2.840.10045.2.1'), 
                new ObjectIdentifier('1.2.840.10045.3.1.7')
            ),
            new BitString($this->point_serialize($key->getPoint()))
        );
        return $sequence->getBinary();
    }

   /**
     * @param PointInterface $point
     * @return string
     */
    public function point_serialize(Point $point): string
    {
        $length = 32 * 2;

        $hexString = '04';
        $hexString .= str_pad(gmp_strval($point->getX(), 16), $length, '0', STR_PAD_LEFT);
        $hexString .= str_pad(gmp_strval($point->getY(), 16), $length, '0', STR_PAD_LEFT);

        return $hexString;
    }


}




class Point{
    /**
     * @var \GMP
     */
    private $x;

    /**
     * @var \GMP
     */
    private $y;


    /**
     * Initialize a new instance
     *
     * @param \GMP                 $x
     * @param \GMP                 $y
     *
     */
    public function __construct( \GMP $x, \GMP $y)
    {
        // $this->curve      = $curve;
        $this->x          = $x;
        $this->y          = $y;
    }

  
    /**
     * {@inheritDoc}
     * @see \Mdanter\Ecc\Primitives\PointInterface::getX()
     */
    public function getX(): \GMP
    {
        return $this->x;
    }

    /**
     * {@inheritDoc}
     * @see \Mdanter\Ecc\Primitives\PointInterface::getY()
     */
    public function getY(): \GMP
    {
        return $this->y;
    }

}

class PublicKey{
    /**
     *
     * @var PointInterface
     */
    private $point;
    /**
     * Initialize a new PublicKey instance.
     *
     * @param  GmpMathInterface  $adapter
     * @param  PointInterface    $point
     */
    public function __construct($point)
    {
        $this->point = $point;
        // $this->adapter = $adapter;


        // //TO DO security issue partial public key validation routine
        // if ($adapter->cmp($point->getX(), gmp_init(0, 10)) < 0 || $adapter->cmp($this->curve->getPrime(), $point->getX()) < 0
        //     || $adapter->cmp($point->getY(), gmp_init(0, 10)) < 0 || $adapter->cmp($this->curve->getPrime(), $point->getY()) < 0
        // ) {
        //     throw new PublicKeyException($generator, $point, "Point has x and y out of range.");
        // }

        // Sanity check. Point (x,y) values are qualified against it's
        // generator and curve. Here we ensure the Point and Generator
        // are the same.
        // if (!$generator->getCurve()->equals($point->getCurve())) {
        //     throw new PublicKeyException($generator, $point, "Curve for given point not in common with GeneratorPoint");
        // }
    }
    /**
     * {@inheritDoc}
     * @see \Mdanter\Ecc\Crypto\Key\PublicKeyInterface::getPoint()
     */
    public function getPoint(): Point
    {
        return $this->point;
    }

}



