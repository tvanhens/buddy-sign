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
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-40
;; - https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40

(ns buddy.sign.jws
  "Json Web Signature implementation."
  (:require [buddy.core.codecs :as codecs]
            [buddy.sign.jws :as jws]
            [clojure.string :as str]
            [cheshire.core :as json]
            [cats.monad.either :as either])
  (:import clojure.lang.Keyword))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- generate-cek
  [{:keys [alg key]}]
  (cond
    (= alg :dir)
    (if (nil? key)
      (either/left "Key should not be empty for :dir alg.")
      (either/right (codecs/->byte-array key)))))

(defn- encrypt-cek
  [^bytes cek {:keys [alg]}]
  (cond
    (= alg :dir)
    (byte-array 0)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn encode
  "Encrypt then sign arbitrary length string/byte array using
  json web encryption."
  [claims key & [{:keys [alg enc exp nbf iat zip key]
                  :or {alg :dir zip false
                       enc :a128cbc-hs256}
                  :as options}]]
  {:pre [(map? claims)]}
  (mlet [cek (generate-cek options)
         ecek (-> (encrypt-cek cek options)
                  (codecs/bytes->safebase64))
         iv   (nonce/random-nonce 32)

         header (encode-header alg)
        claims (encode-claims claims exp nbf iat)
        signature (calculate-signature key alg header claims)]
    (either/right (str/join "." [header claims signature]))))

(defn decode
  "Given a signed and encrypted message, verify it
  and return the decoded and decrypted claims.

  This function returns a monadic either instance,
  and if some error is happens in process of decoding
  and verification, it will be reported in an
  either/left instance."
  [input pkey & [{:keys [max-age] :as opts}]]
  {:pre [(string? input)]}
  (let [[header claims signature] (str/split input #"\." 3)
        candidate (str/join "." [header claims])
        header (parse-header header)
        claims (parse-claims claims)
        algorithm (parse-algorithm header)
        signature (codecs/safebase64->bytes signature)
        verifier (get-verifier-for-algorithm algorithm)
        result (verifier candidate signature pkey)]
    (if (false? result)
      (either/left "Invalid token.")
      (let [now (to-timestamp (jodat/now))]
        (cond
          (and (:exp claims) (> now (:exp claims)))
          (either/left (format "Token is older than :exp (%s)" (:exp claims)))

          (and (:nbf claims) (> now (:nbf claims)))
          (either/left (format "Token is older than :nbf (%s)" (:nbf claims)))

          (and (:iat claims) (number? max-age) (< (- now (:iat claims)) max-age))
          (either/left (format "Token is older than :iat (%s)" (:iat claims)))

          :else
          (either/right claims))))))

(defn sign
  "Not monadic version of encode."
  [& args]
  (either/from-either (apply encode args)))

(defn unsign
  "Not monadic version of decode."
  [& args]
  (let [result (apply decode args)]
    (when (either/right? result)
      result)))
