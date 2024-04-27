<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test\Decrypter;

use Facile\JoseVerifier\Decrypter\TokenDecrypter;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Facile\JoseVerifier\Test\AbstractJwtTestCase;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWESerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\NestedToken\NestedTokenBuilder;
use Jose\Component\NestedToken\NestedTokenLoader;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer as JWSSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

use function Facile\JoseVerifier\jose_secret_key;
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

class TokenDecrypterTest extends AbstractJwtTestCase
{
    public function testDecryptWithAsyToken(): void
    {
        $payload = [
            'foo' => 'bar',
        ];
        $jwsSerializerManager = new JWSSerializerManager([new JWSSerializer()]);
        $jweSerializerManager = new JWESerializerManager([new JWESerializer()]);
        $algorithmManager = new AlgorithmManager([
            new RS256(),
            new RSAOAEP(),
            new A128GCM(),
        ]);
        $compressionMethodManager = new CompressionMethodManager();
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $jweBuilder = new JWEBuilder($algorithmManager, $algorithmManager, $compressionMethodManager);

        $builder = new NestedTokenBuilder($jweBuilder, $jweSerializerManager, $jwsBuilder, $jwsSerializerManager);

        $sigKey = JWKFactory::createRSAKey(2_048, [
            'alg' => 'RS256',
            'use' => 'sig',
        ]);

        $encKey = JWKFactory::createRSAKey(2_048, [
            'alg' => 'RSA-OAEP',
            'use' => 'enc',
        ]);

        $token = $builder->create(
            json_encode($payload),
            [[
                'key' => $sigKey,
                'protected_header' => ['alg' => 'RS256'],
            ]],
            'jws_compact',
            ['alg' => 'RSA-OAEP', 'enc' => 'A128GCM'],
            [],
            [[
                'key' => $encKey,
            ]],
            'jwe_compact'
        );

        $tokenDecrypter = (new \Facile\JoseVerifier\Decrypter\TokenDecrypter())
            ->withExpectedAlg('RSA-OAEP')
            ->withExpectedEnc('A128GCM')
            ->withJwksProvider(new MemoryJwksProvider(['keys' => [$encKey->all()]]));

        $serializer = new JWSSerializer();
        $result = $serializer->unserialize($tokenDecrypter->decrypt($token))->getPayload();

        $this->assertSame($payload, json_decode($result, true));
    }

    public function testCreateWithSymNestedToken(): void
    {
        $payload = [
            'foo' => 'bar',
        ];
        $secret = 'foobar';

        $jwsSerializerManager = new JWSSerializerManager([new JWSSerializer()]);
        $jweSerializerManager = new JWESerializerManager([new JWESerializer()]);
        $algorithmManager = new AlgorithmManager([
            new RS256(),
            new RSAOAEP(),
            new A128GCM(),
            new HS256(),
            new Dir(),
        ]);
        $compressionMethodManager = new CompressionMethodManager();
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $jweBuilder = new JWEBuilder($algorithmManager, $algorithmManager, $compressionMethodManager);

        $builder = new NestedTokenBuilder($jweBuilder, $jweSerializerManager, $jwsBuilder, $jwsSerializerManager);

        $sigKey = JWKFactory::createRSAKey(2_048, [
            'alg' => 'RS256',
            'use' => 'sig',
        ]);

        $encKey = jose_secret_key($secret, 'A128GCM');

        $token = $builder->create(
            json_encode($payload),
            [[
                'key' => $sigKey,
                'protected_header' => ['alg' => 'RS256'],
            ]],
            'jws_compact',
            ['alg' => 'dir', 'enc' => 'A128GCM'],
            [],
            [[
                'key' => $encKey,
            ]],
            'jwe_compact'
        );

        $tokenDecrypter = (new TokenDecrypter())
            ->withExpectedAlg('dir')
            ->withExpectedEnc('A128GCM')
            ->withClientSecret($secret);

        $serializer = new JWSSerializer();
        $result = $serializer->unserialize($tokenDecrypter->decrypt($token))->getPayload();

        $this->assertSame($payload, json_decode($result, true));
    }

    protected function jwksToArray(JWKSet $jwks): array
    {
        return json_decode(json_encode($jwks), true);
    }

    public function decryptNestedToken(string $token, array $sigJwks, array $encJwks): array
    {
        $jwsSerializerManager = new JWSSerializerManager([new JWSSerializer()]);
        $jweSerializerManager = new JWESerializerManager([new JWESerializer()]);
        $algorithmManager = new AlgorithmManager([
            new RS256(),
            new RSAOAEP(),
            new A128GCM(),
            new HS256(),
            new Dir(),
        ]);
        $compressionMethodManager = new CompressionMethodManager();
        $jweDecrypter = new JWEDecrypter($algorithmManager, $algorithmManager, $compressionMethodManager);
        $jweLoader = new JWELoader(
            $jweSerializerManager,
            $jweDecrypter,
            null
        );
        $jwsVerifier = new JWSVerifier($algorithmManager);
        $jwsLoader = new JWSLoader($jwsSerializerManager, $jwsVerifier, null);
        $nestedTokenLoader = new NestedTokenLoader($jweLoader, $jwsLoader);

        return json_decode(
            $nestedTokenLoader->load($token, JWKSet::createFromKeyData($encJwks), JWKSet::createFromKeyData($sigJwks))
                ->getPayload(),
            true,
            JSON_THROW_ON_ERROR
        );
    }
}
