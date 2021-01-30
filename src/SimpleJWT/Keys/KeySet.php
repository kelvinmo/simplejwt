<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2021
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

namespace SimpleJWT\Keys;

use SimpleJWT\JWE;
use SimpleJWT\Crypt\CryptException;

/**
 * A class representing a JSON web key set.
 *
 * This class supports plaintext JSON web key sets, as well as encrypted JSON web key sets
 * encrypted using PBES2 and JWE compact serialization.
 */
class KeySet {
    /** @var array the keys in this key set */
    protected $keys = [];

    /**
     * Loads a set of keys into the key set.  The set of keys is encoded
     * in JSON Web Key Set (JWKS) format.
     *
     * @param string $jwk the JSON web key set to load
     * @param string $password the password, if the key set is password protected
     * @param string $alg the algorithm, if the key set is password protected
     * @throws KeyException if there is an error in reading a key
     */
    function load($jwk, $password = null, $alg = 'PBES2-HS256+A128KW') {
        if ($password != null) {
            $keys = KeySet::createFromSecret($password, 'bin');
            try {
                $jwe = JWE::decrypt($jwk, $keys, $alg);
                $jwk = $jwe->getPlaintext();
            } catch (CryptException $e) {
                throw new KeyException('Cannot decrypt key set', 0, $e);
            }
        }

        $data = json_decode($jwk, true);
        foreach ($data['keys'] as $key_data) {
            $this->keys[] = KeyFactory::create($key_data, 'php');
        }
    }

    /**
     * Returns a key set as a JSON web key set.
     *
     * If `$password` is null, an unencrypted JSON structure is returned.
     *
     * If `$password` is not null, a JWE is created using PBES2 key encryption.
     *
     * @param string $password the password
     * @return string the key set
     */
    function toJWKS($password = null) {
        $result = array_map(function($key) {
            return $key->getKeyData();
        }, $this->keys);
        $json = json_encode(['keys' => $result]);
        if ($password == null) return $json;

        $keys = KeySet::createFromSecret($password, 'bin');
        $headers = [
            'alg' => 'PBES2-HS256+A128KW',
            'enc' => 'A128CBC-HS256',
            'cty' => 'jwk-set+json'
        ];
        $jwe = new JWE($headers, $json);
        return $jwe->encrypt($keys);
    }

    /**
     * Adds a key to the key set.
     *
     * This function checks whether an identical key (whether by key ID or by
     * key contents) already exists in the key set.
     *
     * @param Key $key the key to add
     * @throws KeyException if there is an identical key
     */
    function add($key) {
        $thumbnail = $key->getThumbnail();
        foreach ($this->keys as $existing_key) {
            if ($existing_key->getThumbnail() == $thumbnail) throw new KeyException('Key already exists');
            if ($existing_key->getKeyID() == $key->getKeyID()) throw new KeyException('Key already exists');
        }

        $this->keys[] = $key;
    }

    /**
     * Adds all the keys from another key set.
     *
     * This function calls the {@link add()} function on all the keys in the
     * specified key set.
     *
     * @param KeySet $set the key set containing the keys to add
     */
    function addAll($set) {
        foreach ($set->keys as $key) {
            try {
                $this->add($key);
            } catch (KeyException $e) {
                // ignore
            }
        }
    }

    /**
     * Returns all the keys in the key set as `Key` objects
     *
     * @return array an array of keys
     */
    function getKeys() {
        return $this->keys;
    }

    /**
     * Finds a key matching specified key ID.
     *
     * In addition to exact match, this method also supports *fuzzy search*, which
     * matches the beginning of the key ID string
     *
     * @param string $kid the key ID
     * @param bool $fuzzy whether fuzzy search is to be used
     * @return Key the found key, or null
     */
    function getById($kid, $fuzzy = false) {
        $fuzzy_keys = [];

        foreach ($this->keys as $key) {
            if ($key->getKeyId() == $kid) {
                return $key;
            } elseif ($fuzzy && (strpos($key->getKeyId(), $kid) === 0)) {
                $fuzzy_keys[] = $key;
            }
        }
        if (count($fuzzy_keys) == 1) return $fuzzy_keys[0];
        return null;
    }

    /**
     * Finds a key matching specified criteria.
     *
     * The criteria are expressed as an associative array, with the keys being
     * the name of JWK property to match (with optional prefixes set out below),
     * and the values being the value to be matched.  The value may be specified
     * as an array, in which case any element of the array can be matched.
     * 
     * There are also a number of special properties that can be used to match
     * keys:
     * 
     * - {@link Key::SIZE_PROPERTY}, which specifies the length of the key in bits
     * - {@link Key::PUBLIC_PROPERTY}, which is true if the key is an asymmetric public
     *   key
     *
     * A criterion can be mandatory, mandatory-if-present (indicated using a `@`
     * prefix), or optional (indicated using a `~` prefix).  A key matches the
     * criteria if:
     * 
     * - all of the mandatory criteria are fulfilled; and
     * - for each of the mandatory-if-present criterion, if the property is
     *   present in the key, the value matches the one specified in the
     *   criterion.
     * 
     * If there is more than one key in the key set that matches the mandatory
     * and mandatory-if-present criteria, the key which matches
     * the most mandatory-if-present and optional criteria will be returned.
     *
     * @param array $criteria the criteria
     * @return Key the found key, or null
     */
    function get($criteria) {
        $keys = $this->find($criteria);
        if ($keys == null) return null;
        return $keys[0];
    }


    /**
     * Finds a key matching specified criteria.
     *
     * The criteria are expressed as an associative array, with the keys being
     * the name of JWK property to match (with optional prefixes set out below),
     * and the values being the value to be matched.  The value may be specified
     * as an array, in which case any element of the array can be matched.
     * 
     * There are also a number of special properties that can be used to match
     * keys:
     * 
     * - {@link Key::SIZE_PROPERTY}, which specifies the length of the key in bits
     * - {@link Key::PUBLIC_PROPERTY}, which is true if the key is an asymmetric public
     *   key
     *
     * A criterion can be mandatory, mandatory-if-present (indicated using a `@`
     * prefix), or optional (indicated using a `~` prefix).  A key matches the
     * criteria if:
     * 
     * - all of the mandatory criteria are fulfilled; and
     * - for each of the mandatory-if-present criterion, if the property is
     *   present in the key, the value matches the one specified in the
     *   criterion.
     * 
     * If there is more than one key in the key set that matches the mandatory
     * and mandatory-if-present criteria, then the function returns the keys
     * sorted by decreasing order of mandatory-if-present and optional criteria 
     * matched.
     *
     * @param array $criteria the criteria
     * @return array an array of keys that matches the criteria, sorted
     * by decreasing order of optional criteria matched, or null
     */
    protected function find($criteria) {
        $results = [];

        // 1. Sort the criteria into mandatory, mandatory-if-present
        //    and optional criteria
        $mandatory = [];
        $mandatory_if_present = [];
        $optional = [];

        foreach ($criteria as $property => $value) {
            if ($property[0] == '~') {
                $optional[substr($property, 1)] = $value;
            } elseif ($property[0] == '@') {
                $mandatory_if_present[substr($property, 1)] = $value;
            } else {
                $mandatory[$property] = $value;
            }
        }

        // 2. Mandatory and mandatory-if-present criteria
        foreach ($this->keys as $key) {
            $key_data = $key->getKeyData();
            $key_data[Key::SIZE_PROPERTY] = $key->getSize();
            $key_data[Key::PUBLIC_PROPERTY] = $key->isPublic();
            $kid = $key->getKeyId();

            $found = true;
            foreach ($mandatory as $property => $value) {
                if (!isset($key_data[$property])) {
                    $found = false;
                    break;
                } elseif (!$this->isMatch($value, $key_data[$property])) {
                    $found = false;
                    break;
                }
            }
            foreach ($mandatory_if_present as $property => $value) {
                if (!isset($key_data[$property])) continue;
                if (!$this->isMatch($value, $key_data[$property])) {
                    $found = false;
                    break;
                }
            }
            if ($found) $results[$kid] = $key_data;
        }

        // 3. If zero or one key is found after allowing for mandatory and
        //    mandatory-if-present criteria, return
        if (count($results) == 0) return null;
        if (count($results) == 1) {
            $kids = array_keys($results);
            return [$this->getById($kids[0])];
        }

        // 4. Optional criteria
        $non_mandatory = array_merge($mandatory_if_present, $optional);

        if (count($non_mandatory) == 0) {
            $kids = array_keys($results);
            return array_map(function($kid) {
                return $this->getById($kid);
            }, $kids);
        }

        $results = array_map(function($key_data) use ($non_mandatory) {
            $count = 0;
            foreach ($non_mandatory as $property => $value) {
                if (!isset($key_data[$property])) continue;
                if ($this->isMatch($value, $key_data[$property])) {
                    $count++;
                }
            }
            return $count;
        }, $results);
        arsort($results);
        $kids = array_keys($results);
        return array_map(function($kid) {
            return $this->getById($kid);
        }, $kids);
    }

    /**
     * Determines whether the property value of a key matches that of
     * a criterion in {@link KeySet::find()}.
     * 
     * The matching rules are the following:
     * 
     * - If both `$criterion_value` and `$key_value` are scalars, then a
     *   match occurs if `$criterion_value` is equal to `$key_value`
     * - If `$criterion_value` is a scalar and `$key_value` is an array,
     *   then a match occurs if `$criterion_value` is in `$key_value`
     * - If `$criterion_value` is an array and `$key_value` is a scalar,
     *   then a match occurs if `$key_value` is in `$criterion_value`
     * - If both `$criterion_value` and `$key_value` are arrays, then a
     *   match occurs if any element in `$criterion_value` is in
     *   `$key_value`
     * - Otherwise, there is no match
     * 
     * @param mixed $criterion_value the value of a criterion
     * @param mixed $key_value the value of a property in a key
     * @return bool true if there is match
     */
    protected function isMatch($criterion_value, $key_value) {
        if (is_scalar($criterion_value) && is_scalar($key_value)) {
            return ($criterion_value == $key_value);
        } elseif (is_scalar($criterion_value) && is_array($key_value)) {
            return in_array($criterion_value, $key_value);
        } elseif (is_array($criterion_value) && is_scalar($key_value)) {
            return in_array($key_value, $criterion_value);
        } elseif (is_array($criterion_value) && is_array($key_value)) {
            return (count($key_value) != count($key_value, $criterion_value));
        }
        return false;
    }

    /**
     * Removes a key from the key set
     *
     * @param Key $key the key to remove
     */
    function remove($key) {
        for ($i = 0; $i < count($this->keys); $i++) {
            if ($this->keys[$i]->getThumbnail() == $key->getThumbnail()) {
                unset($this->keys[$i]);
                return;
            }
        }
    }

    /**
     * Returns whether *all* of the keys in the key set are public keys.
     *
     * Whether a key is public is determined by calling the {@link Key::isPublic()}
     * method.
     *
     * @return bool true if all the keys are public
     */
    function isPublic() {
        foreach ($this->keys as $key) {
            if (!$key->isPublic()) return false;
        }
        return true;
    }

    /**
     * Convenience function for creating a `KeySet` from a single symmetric
     * key.
     *
     * @param string $secret the secret
     * @param string $format the format of the secret - see {@link SymmetricKey::__create()}
     * for further details
     * @return KeySet the created key set
     */
    static public function createFromSecret($secret, $format = 'bin') {
        $set = new KeySet();
        $key = new SymmetricKey($secret, $format);
        $set->add($key);
        return $set;
    }
}

?>
