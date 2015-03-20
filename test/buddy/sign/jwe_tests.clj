;; Copyright 2014-2015 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.sign.jwe-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :as codecs]
            [buddy.core.bytes :as bytes]
            [buddy.sign.jwe :as jwe]))

(def secret (codecs/hex->bytes (str "000102030405060708090a0b0c0d0e0f"
                                    "101112131415161718191a1b1c1d1e1f")))

(deftest vectorstests
  (let [secret (codecs/hex->bytes (str "000102030405060708090a0b0c0d0e0f"
                                       "101112131415161718191a1b1c1d1e1f"))
        keymac (codecs/hex->bytes "000102030405060708090a0b0c0d0e0f")
        keyenc (codecs/hex->bytes "101112131415161718191a1b1c1d1e1f")

        iv (codecs/hex->bytes "1af38c2dc2b96ffdd86694092341bc04")
        aad (codecs/hex->bytes (str "546865207365636f6e64207072696e63"
                                    "69706c65206f66204175677573746520"
                                    "4b6572636b686f666673"))
        al (codecs/hex->bytes "0000000000000150")

        p (codecs/hex->bytes (str "41206369706865722073797374656d20"
                                  "6d757374206e6f742062652072657175"
                                  "6972656420746f206265207365637265"
                                  "742c20616e64206974206d7573742062"
                                  "652061626c6520746f2066616c6c2069"
                                  "6e746f207468652068616e6473206f66"
                                  "2074686520656e656d7920776974686f"
                                  "757420696e636f6e76656e69656e6365"))
        e (codecs/hex->bytes (str "c80edfa32ddf39d5ef00c0b468834279"
                                  "a2e46a1b8049f792f76bfe54b903a9c9"
                                  "a94ac9b47ad2655c5f10f9aef71427e2"
                                  "fc6f9b3f399a221489f16362c7032336"
                                  "09d45ac69864e3321cf82935ac4096c8"
                                  "6e133314c54019e8ca7980dfa4b9cf1b"
                                  "384c486f3a54c51078158ee5d79de59f"
                                  "bd34d848b3d69550a67646344427ade5"
                                  "4b8851ffb598f7f80074b9473c82e2db"))
        m (codecs/hex->bytes (str "652c3fa36b0a7c5b3219fab3a30bc1c4"
                                  "e6e54582476515f0ad9f75a2b71c73ef"))
        t (codecs/hex->bytes (str "652c3fa36b0a7c5b3219fab3a30bc1c4"))]

    ;; Test `extract-encryption-key`
    (let [function #'jwe/extract-encryption-key
          result (function secret)]
      (is (bytes/equals? result keyenc)))

    ;; Test `calculate-aad-length`
    (let [function #'jwe/calculate-aad-length
          result (function aad)]
      (is (bytes/equals? result al)))

    ;; Test `generate-ciphertext`
    (let [function #'jwe/generate-ciphertext
          result (function p secret iv aad)]
      (is (bytes/equals? result e)))

    ;; Test `generate-authtag`
    (let [function #'jwe/generate-authtag
          result (function e secret iv aad)]
      (is (bytes/equals? result t)))
))

(deftest experiments
  (let [result (jwe/encode {:foo :bar} {:key secret})]
    (println result)))
