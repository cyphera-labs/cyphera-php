<?php

declare(strict_types=1);

namespace Cyphera;

/**
 * Cyphera SDK — configuration-driven protect/access API.
 */
class Cyphera
{
    private const ALPHABETS = [
        'digits' => '0123456789',
        'alpha_lower' => 'abcdefghijklmnopqrstuvwxyz',
        'alpha_upper' => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'alpha' => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'alphanumeric' => '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    ];

    /** @var array<string, array<string, mixed>> */
    private array $configurations = [];
    /** @var array<string, string> header -> configuration name */
    private array $headerIndex = [];
    /** @var array<string, string> name -> key bytes */
    private array $keys = [];

    private function __construct(array $config)
    {
        // Load keys
        foreach (($config['keys'] ?? []) as $name => $val) {
            if (is_string($val)) {
                $this->keys[$name] = hex2bin($val);
            } elseif (isset($val['material'])) {
                $this->keys[$name] = hex2bin($val['material']);
            } elseif (isset($val['source'])) {
                $this->keys[$name] = self::resolveKeySource($name, $val);
            } else {
                throw new \InvalidArgumentException("Key '{$name}' must have either 'material' or 'source'");
            }
        }

        // Load configurations + build header index
        foreach (($config['configurations'] ?? []) as $name => $cfg) {
            $headerEnabled = ($cfg['header_enabled'] ?? true) !== false;
            $header = $cfg['header'] ?? null;

            if ($headerEnabled && empty($header)) {
                throw new \InvalidArgumentException("Configuration '{$name}' has header_enabled=true but no header specified");
            }

            if ($headerEnabled && $header !== null) {
                if (isset($this->headerIndex[$header])) {
                    throw new \InvalidArgumentException("Header collision: '{$header}' used by both '{$this->headerIndex[$header]}' and '{$name}'");
                }
                $this->headerIndex[$header] = $name;
            }

            $this->configurations[$name] = [
                'engine' => $cfg['engine'] ?? 'ff1',
                'alphabet' => self::resolveAlphabet($cfg['alphabet'] ?? null),
                'key_ref' => $cfg['key_ref'] ?? null,
                'header' => $header,
                'header_enabled' => $headerEnabled,
                'pattern' => $cfg['pattern'] ?? null,
                'algorithm' => $cfg['algorithm'] ?? 'sha256',
            ];
        }
    }

    public static function load(): self
    {
        $envPath = getenv('CYPHERA_CONFIG_FILE');
        if ($envPath && file_exists($envPath)) {
            return self::fromFile($envPath);
        }
        if (file_exists('cyphera.json')) {
            return self::fromFile('cyphera.json');
        }
        if (file_exists('/etc/cyphera/cyphera.json')) {
            return self::fromFile('/etc/cyphera/cyphera.json');
        }
        throw new \RuntimeException(
            'No configuration file found. Checked: CYPHERA_CONFIG_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json'
        );
    }

    public static function fromFile(string $path): self
    {
        $json = file_get_contents($path);
        if ($json === false) {
            throw new \RuntimeException("Failed to read configuration file: {$path}");
        }
        $config = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        return new self($config);
    }

    public static function fromConfig(array $config): self
    {
        return new self($config);
    }

    public function protect(string $value, string $configurationName): string
    {
        $configuration = $this->getConfiguration($configurationName);

        return match ($configuration['engine']) {
            'ff1' => $this->protectFpe($value, $configuration, false),
            'ff3' => $this->protectFpe($value, $configuration, true),
            'mask' => $this->protectMask($value, $configuration),
            'hash' => $this->protectHash($value, $configuration),
            default => throw new \InvalidArgumentException("Unknown engine: {$configuration['engine']}"),
        };
    }

    public function access(string $protectedValue, ?string $configurationName = null): string
    {
        if ($configurationName !== null) {
            $configuration = $this->getConfiguration($configurationName);
            return $this->accessFpe($protectedValue, $configuration, true);
        }

        // Header-based lookup — longest headers first
        $headers = array_keys($this->headerIndex);
        usort($headers, fn($a, $b) => strlen($b) - strlen($a));

        foreach ($headers as $header) {
            if (strlen($protectedValue) > strlen($header) && str_starts_with($protectedValue, $header)) {
                $configuration = $this->getConfiguration($this->headerIndex[$header]);
                return $this->accessFpe($protectedValue, $configuration);
            }
        }

        throw new \InvalidArgumentException('No matching header found. Use access($value, $configurationName) for values without a header.');
    }

    // ── FPE ──

    private function protectFpe(string $value, array $configuration, bool $isFF3): string
    {
        $key = $this->resolveKey($configuration['key_ref']);
        $alphabet = $configuration['alphabet'];

        [$encryptable, $positions, $chars] = $this->extractPassthroughs($value, $alphabet);

        if ($encryptable === '') {
            throw new \InvalidArgumentException('No encryptable characters in input');
        }

        if ($isFF3) {
            $cipher = new FF3($key, str_repeat("\x00", 8), $alphabet);
        } else {
            $cipher = new FF1($key, '', $alphabet);
        }
        $encrypted = $cipher->encrypt($encryptable);

        $result = $this->reinsertPassthroughs($encrypted, $positions, $chars);

        if ($configuration['header_enabled'] && $configuration['header'] !== null) {
            return $configuration['header'] . $result;
        }
        return $result;
    }

    private function accessFpe(string $protectedValue, array $configuration, bool $explicitConfiguration = false): string
    {
        if (!in_array($configuration['engine'], ['ff1', 'ff3'], true)) {
            throw new \InvalidArgumentException("Cannot reverse '{$configuration['engine']}' — not reversible");
        }

        $key = $this->resolveKey($configuration['key_ref']);
        $alphabet = $configuration['alphabet'];

        $withoutHeader = $protectedValue;
        if (!$explicitConfiguration && $configuration['header_enabled'] && $configuration['header'] !== null) {
            $withoutHeader = substr($protectedValue, strlen($configuration['header']));
        }

        [$encryptable, $positions, $chars] = $this->extractPassthroughs($withoutHeader, $alphabet);

        if ($configuration['engine'] === 'ff3') {
            $cipher = new FF3($key, str_repeat("\x00", 8), $alphabet);
        } else {
            $cipher = new FF1($key, '', $alphabet);
        }
        $decrypted = $cipher->decrypt($encryptable);

        return $this->reinsertPassthroughs($decrypted, $positions, $chars);
    }

    // ── Mask ──

    private function protectMask(string $value, array $configuration): string
    {
        $pattern = $configuration['pattern'];
        if (empty($pattern)) {
            throw new \InvalidArgumentException("Mask configuration requires 'pattern'");
        }

        $len = mb_strlen($value);
        return match ($pattern) {
            'last4', 'last_4' => str_repeat('*', max(0, $len - 4)) . mb_substr($value, -min(4, $len)),
            'last2', 'last_2' => str_repeat('*', max(0, $len - 2)) . mb_substr($value, -min(2, $len)),
            'first1', 'first_1' => mb_substr($value, 0, min(1, $len)) . str_repeat('*', max(0, $len - 1)),
            'first3', 'first_3' => mb_substr($value, 0, min(3, $len)) . str_repeat('*', max(0, $len - 3)),
            default => str_repeat('*', $len),
        };
    }

    // ── Hash ──

    private function protectHash(string $value, array $configuration): string
    {
        $algo = strtolower(str_replace('-', '', $configuration['algorithm']));
        $algoMap = ['sha256' => 'sha256', 'sha384' => 'sha384', 'sha512' => 'sha512'];
        $hashAlgo = $algoMap[$algo] ?? null;
        if ($hashAlgo === null) {
            throw new \InvalidArgumentException("Unsupported hash algorithm: {$configuration['algorithm']}");
        }

        $data = $value;

        if (!empty($configuration['key_ref'])) {
            $key = $this->resolveKey($configuration['key_ref']);
            return hash_hmac($hashAlgo, $data, $key);
        }

        return hash($hashAlgo, $data);
    }

    // ── Helpers ──

    private function getConfiguration(string $name): array
    {
        if (!isset($this->configurations[$name])) {
            throw new \InvalidArgumentException("Unknown configuration: {$name}");
        }
        return $this->configurations[$name];
    }

    private function resolveKey(?string $keyRef): string
    {
        if (empty($keyRef)) {
            throw new \InvalidArgumentException('No key_ref in configuration');
        }
        if (!isset($this->keys[$keyRef])) {
            throw new \InvalidArgumentException("Unknown key: {$keyRef}");
        }
        return $this->keys[$keyRef];
    }

    private const CLOUD_SOURCES = ['aws-kms', 'gcp-kms', 'azure-kv', 'vault'];

    private static function resolveKeySource(string $name, array $config): string
    {
        $source = $config['source'];

        if ($source === 'env') {
            $var = $config['var'] ?? null;
            if (!$var) throw new \InvalidArgumentException("Key '{$name}': source 'env' requires 'var' field");
            $val = getenv($var);
            if ($val === false || $val === '') throw new \InvalidArgumentException("Key '{$name}': environment variable '{$var}' is not set");
            $encoding = $config['encoding'] ?? 'hex';
            if ($encoding === 'base64') return base64_decode($val, true);
            return hex2bin($val);
        }

        if ($source === 'file') {
            $path = $config['path'] ?? null;
            if (!$path) throw new \InvalidArgumentException("Key '{$name}': source 'file' requires 'path' field");
            $raw = trim(file_get_contents($path));
            $encoding = $config['encoding'] ?? (str_ends_with($path, '.b64') || str_ends_with($path, '.base64') ? 'base64' : 'hex');
            if ($encoding === 'base64') return base64_decode($raw, true);
            return hex2bin($raw);
        }

        if (in_array($source, self::CLOUD_SOURCES, true)) {
            if (!class_exists('Cyphera\\Keychain\\KeychainResolver')) {
                throw new \RuntimeException(
                    "Key '{$name}' requires source '{$source}' but cyphera-keychain is not installed.\n" .
                    "Install it: composer require cyphera/cyphera-keychain"
                );
            }
            return \Cyphera\Keychain\KeychainResolver::resolve($source, $config);
        }

        throw new \InvalidArgumentException("Key '{$name}': unknown source '{$source}'. Valid: env, file, " . implode(', ', self::CLOUD_SOURCES));
    }

    private static function resolveAlphabet(?string $name): string
    {
        if ($name === null || $name === '') {
            return self::ALPHABETS['alphanumeric'];
        }
        return self::ALPHABETS[$name] ?? $name;
    }

    /**
     * @return array{string, int[], string[]}
     */
    private function extractPassthroughs(string $value, string $alphabet): array
    {
        $encryptable = '';
        $positions = [];
        $chars = [];
        foreach (mb_str_split($value) as $i => $c) {
            if (mb_strpos($alphabet, $c) !== false) {
                $encryptable .= $c;
            } else {
                $positions[] = $i;
                $chars[] = $c;
            }
        }
        return [$encryptable, $positions, $chars];
    }

    /**
     * @param int[] $positions
     * @param string[] $chars
     */
    private function reinsertPassthroughs(string $encrypted, array $positions, array $chars): string
    {
        $result = mb_str_split($encrypted);
        foreach ($positions as $i => $pos) {
            if ($pos <= count($result)) {
                array_splice($result, $pos, 0, [$chars[$i]]);
            } else {
                $result[] = $chars[$i];
            }
        }
        return implode('', $result);
    }
}
