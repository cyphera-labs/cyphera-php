<?php

declare(strict_types=1);

namespace Cyphera;

/**
 * Cyphera SDK — policy-driven protect/access API.
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
    private array $policies = [];
    /** @var array<string, string> tag -> policy name */
    private array $tagIndex = [];
    /** @var array<string, string> name -> key bytes */
    private array $keys = [];

    private function __construct(array $config)
    {
        // Load keys
        foreach (($config['keys'] ?? []) as $name => $val) {
            $material = is_string($val) ? $val : ($val['material'] ?? '');
            $this->keys[$name] = hex2bin($material);
        }

        // Load policies + build tag index
        foreach (($config['policies'] ?? []) as $name => $pol) {
            $tagEnabled = ($pol['tag_enabled'] ?? true) !== false;
            $tag = $pol['tag'] ?? null;

            if ($tagEnabled && empty($tag)) {
                throw new \InvalidArgumentException("Policy '{$name}' has tag_enabled=true but no tag specified");
            }

            if ($tagEnabled && $tag !== null) {
                if (isset($this->tagIndex[$tag])) {
                    throw new \InvalidArgumentException("Tag collision: '{$tag}' used by both '{$this->tagIndex[$tag]}' and '{$name}'");
                }
                $this->tagIndex[$tag] = $name;
            }

            $this->policies[$name] = [
                'engine' => $pol['engine'] ?? 'ff1',
                'alphabet' => self::resolveAlphabet($pol['alphabet'] ?? null),
                'key_ref' => $pol['key_ref'] ?? null,
                'tag' => $tag,
                'tag_enabled' => $tagEnabled,
                'pattern' => $pol['pattern'] ?? null,
                'algorithm' => $pol['algorithm'] ?? 'sha256',
            ];
        }
    }

    public static function load(): self
    {
        $envPath = getenv('CYPHERA_POLICY_FILE');
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
            'No policy file found. Checked: CYPHERA_POLICY_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json'
        );
    }

    public static function fromFile(string $path): self
    {
        $json = file_get_contents($path);
        if ($json === false) {
            throw new \RuntimeException("Failed to read policy file: {$path}");
        }
        $config = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        return new self($config);
    }

    public static function fromConfig(array $config): self
    {
        return new self($config);
    }

    public function protect(string $value, string $policyName): string
    {
        $policy = $this->getPolicy($policyName);

        return match ($policy['engine']) {
            'ff1' => $this->protectFpe($value, $policy, false),
            'ff3' => $this->protectFpe($value, $policy, true),
            'mask' => $this->protectMask($value, $policy),
            'hash' => $this->protectHash($value, $policy),
            default => throw new \InvalidArgumentException("Unknown engine: {$policy['engine']}"),
        };
    }

    public function access(string $protectedValue, ?string $policyName = null): string
    {
        if ($policyName !== null) {
            $policy = $this->getPolicy($policyName);
            return $this->accessFpe($protectedValue, $policy);
        }

        // Tag-based lookup — longest tags first
        $tags = array_keys($this->tagIndex);
        usort($tags, fn($a, $b) => strlen($b) - strlen($a));

        foreach ($tags as $tag) {
            if (strlen($protectedValue) > strlen($tag) && str_starts_with($protectedValue, $tag)) {
                $policy = $this->getPolicy($this->tagIndex[$tag]);
                return $this->accessFpe($protectedValue, $policy);
            }
        }

        throw new \InvalidArgumentException('No matching tag found. Use access($value, $policyName) for untagged values.');
    }

    // ── FPE ──

    private function protectFpe(string $value, array $policy, bool $isFF3): string
    {
        $key = $this->resolveKey($policy['key_ref']);
        $alphabet = $policy['alphabet'];

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

        if ($policy['tag_enabled'] && $policy['tag'] !== null) {
            return $policy['tag'] . $result;
        }
        return $result;
    }

    private function accessFpe(string $protectedValue, array $policy): string
    {
        if (!in_array($policy['engine'], ['ff1', 'ff3'], true)) {
            throw new \InvalidArgumentException("Cannot reverse '{$policy['engine']}' — not reversible");
        }

        $key = $this->resolveKey($policy['key_ref']);
        $alphabet = $policy['alphabet'];

        $withoutTag = $protectedValue;
        if ($policy['tag_enabled'] && $policy['tag'] !== null) {
            $withoutTag = substr($protectedValue, strlen($policy['tag']));
        }

        [$encryptable, $positions, $chars] = $this->extractPassthroughs($withoutTag, $alphabet);

        if ($policy['engine'] === 'ff3') {
            $cipher = new FF3($key, str_repeat("\x00", 8), $alphabet);
        } else {
            $cipher = new FF1($key, '', $alphabet);
        }
        $decrypted = $cipher->decrypt($encryptable);

        return $this->reinsertPassthroughs($decrypted, $positions, $chars);
    }

    // ── Mask ──

    private function protectMask(string $value, array $policy): string
    {
        $pattern = $policy['pattern'];
        if (empty($pattern)) {
            throw new \InvalidArgumentException("Mask policy requires 'pattern'");
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

    private function protectHash(string $value, array $policy): string
    {
        $algo = strtolower(str_replace('-', '', $policy['algorithm']));
        $algoMap = ['sha256' => 'sha256', 'sha384' => 'sha384', 'sha512' => 'sha512'];
        $hashAlgo = $algoMap[$algo] ?? null;
        if ($hashAlgo === null) {
            throw new \InvalidArgumentException("Unsupported hash algorithm: {$policy['algorithm']}");
        }

        $data = $value;

        if (!empty($policy['key_ref'])) {
            $key = $this->resolveKey($policy['key_ref']);
            return hash_hmac($hashAlgo, $data, $key);
        }

        return hash($hashAlgo, $data);
    }

    // ── Helpers ──

    private function getPolicy(string $name): array
    {
        if (!isset($this->policies[$name])) {
            throw new \InvalidArgumentException("Unknown policy: {$name}");
        }
        return $this->policies[$name];
    }

    private function resolveKey(?string $keyRef): string
    {
        if (empty($keyRef)) {
            throw new \InvalidArgumentException('No key_ref in policy');
        }
        if (!isset($this->keys[$keyRef])) {
            throw new \InvalidArgumentException("Unknown key: {$keyRef}");
        }
        return $this->keys[$keyRef];
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
