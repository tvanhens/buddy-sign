;; Copyright (c) 2014-2015 Andrey Antukh <niwi@niwi.be>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

;; Links to rfcs:
;; - http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40
;; - http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05

(ns buddy.sign.jwe
  "Json Web Encryption."
  (:require [buddy.core.codecs :as codecs]
            [buddy.sign.jws :as jws]
            [buddy.core.bytes :as bytes]
            [buddy.core.nonce :as nonce]
            [buddy.core.crypto :as crypto]
            [buddy.core.mac.hmac :as hmac]
            [buddy.core.padding :as padding]
            [clojure.string :as str]
            [cheshire.core :as json]
            [cats.core :as m]
            [cats.monad.either :as either])
  (:import clojure.lang.Keyword
           java.nio.ByteBuffer))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Crypto primitives/helpers.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- split-by-blocksize
  "Split a byte array in blocksize blocks.
  Given a arbitrary size bytearray and block size in bytes,
  returns a lazy sequence of bytearray blocks of blocksize
  size. If last block does not have enought data for fill
  all block, it is padded using zerobyte padding."
  [^bytes input ^long blocksize]
  (let [inputsize (count input)]
    (loop [cursormin 0
           cursormax blocksize
           remain inputsize
           result []]
      (cond
        (= remain 0)
        (conj result (byte-array blocksize))

        (< remain blocksize)
        (let [buffer (byte-array blocksize)]
          (println input cursormin buffer 0 remain)
          (System/arraycopy input cursormin buffer 0 remain)
          (conj result buffer))

        ;; (= remain blocksize)
        ;; (let [buffer (byte-array blocksize)]
        ;;   (System/arraycopy input cursormin buffer 0 remain)
        ;;   (recur cursormax
        ;;          (+ cursormax blocksize)
        ;;          (- inputsize cursormax)
        ;;          (conj result buffer)))

        (>= remain blocksize)
        (let [buffer (byte-array blocksize)]
          (System/arraycopy input cursormin buffer 0 blocksize)
          (recur cursormax
                 (+ cursormax blocksize)
                 (- inputsize cursormax)
                 (conj result buffer)))))))

(defn- encrypt
  [input key iv]
  (let [cipher (crypto/block-cipher :aes :cbc)
        blocksize (crypto/get-block-size cipher)
        blocks (split-by-blocksize input blocksize)]
    (crypto/initialize! cipher {:op :encrypt :iv iv :key key})
    (apply bytes/concat
           (reduce (fn [acc block]
                     (let [padnum (padding/count block :zerobyte)
                           length (count block)]
                       (when (> padnum 0)
                         (padding/pad! block (- length padnum) :pkcs7))
                       (let [eblock (crypto/process-block! cipher block)]
                         (conj acc eblock))))
                   [] blocks))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmulti generate-cek :alg)
(defmethod generate-cek :dir
  [{:keys [key]}]
  (codecs/->byte-array key))

(defmulti encrypt-cek :alg)
(defmethod encrypt-cek :dir
  [{:keys [alg cek]}]
  (byte-array 0))

(defn generate-header
  [{:keys [alg enc]}]
  (-> {:alg (condp = alg
              :dir "dir"
              (str/upper-case (name alg)))
       :enc (str/upper-case (name enc))}
      (json/generate-string)
      (codecs/str->bytes)))

(defmulti generate-iv :enc)
(defmethod generate-iv :a128cbc-hs256 [_] (nonce/random-bytes 16))

(defn extract-encryption-key
  [secret]
  {:pre [(bytes/bytes? secret)]}
  (bytes/slice secret 16 32))

(defn extract-authentication-key
  [secret]
  {:pre [(bytes/bytes? secret)]}
  (bytes/slice secret 0 16))

(defn calculate-aad-length
  [aad]
  (let [length (* (count aad) 8)
        buffer (ByteBuffer/allocate 8)]
    (.putLong buffer length)
    (.array buffer)))

(defn- generate-ciphertext
  [plaintext secret iv aad]
  (let [ek (extract-encryption-key secret)
    (encrypt plaintext ek iv)))

(defn- generate-authtag
  [ciphertext secret iv aad]
  (let [al (calculate-aad-length aad)
        mk (extract-authentication-key secret)
        data (bytes/concat aad iv ciphertext al)
        mac (hmac/hash data mk :sha256)]
    ;; TODO: truncate depends on keysize
    (bytes/slice mac 0 16)))

(defn- generate-plaintext
  [claims]
  (-> (json/generate-string claims)
      (codecs/str->bytes)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn encode
  "Encrypt then sign arbitrary length string/byte array using
  json web encryption."
  [claims & [{:keys [alg enc exp nbf iat zip key]
              :or {alg :dir zip false
                   enc :a128cbc-hs256}
              :as options}]]
  {:pre [(map? claims)]}
  (let [scek (generate-cek {:key key :alg alg})
        ecek (encrypt-cek {:cek scek :alg alg})
        iv (generate-iv {:enc enc})
        header (generate-header {:alg alg :enc enc})
        plaintext (generate-plaintext claims)
        ciphertext (generate-ciphertext plaintext scek iv header)
        authtag (generate-authtag ciphertext scek iv header)]
    (str/join "." [(codecs/bytes->safebase64 header)
                   (codecs/bytes->safebase64 ecek)
                   (codecs/bytes->safebase64 iv)
                   (codecs/bytes->safebase64 ciphertext)
                   (codecs/bytes->safebase64 authtag)])))

;; (defn decode
;;   "Given a signed and encrypted message, verify it
;;   and return the decoded and decrypted claims.

;;   This function returns a monadic either instance,
;;   and if some error is happens in process of decoding
;;   and verification, it will be reported in an
;;   either/left instance."
;;   [input pkey & [{:keys [max-age] :as opts}]]
;;   {:pre [(string? input)]}
;;   (let [[header claims signature] (str/split input #"\." 3)
;;         candidate (str/join "." [header claims])
;;         header (parse-header header)
;;         claims (parse-claims claims)
;;         algorithm (parse-algorithm header)
;;         signature (codecs/safebase64->bytes signature)
;;         verifier (get-verifier-for-algorithm algorithm)
;;         result (verifier candidate signature pkey)]
;;     (if (false? result)
;;       (either/left "Invalid token.")
;;       (let [now (to-timestamp (jodat/now))]
;;         (cond
;;           (and (:exp claims) (> now (:exp claims)))
;;           (either/left (format "Token is older than :exp (%s)" (:exp claims)))

;;           (and (:nbf claims) (> now (:nbf claims)))
;;           (either/left (format "Token is older than :nbf (%s)" (:nbf claims)))

;;           (and (:iat claims) (number? max-age) (< (- now (:iat claims)) max-age))
;;           (either/left (format "Token is older than :iat (%s)" (:iat claims)))

;;           :else
;;           (either/right claims))))))

;; (defn sign
;;   "Not monadic version of encode."
;;   [& args]
;;   (either/from-either (apply encode args)))

;; (defn unsign
;;   "Not monadic version of decode."
;;   [& args]
;;   (let [result (apply decode args)]
;;     (when (either/right? result)
;;       result)))
