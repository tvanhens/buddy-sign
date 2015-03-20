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
            [buddy.sign.jwe :as jwe]))

(def secret (codecs/hex->bytes (str "000102030405060708090a0b0c0d0e0f"
                                    "101112131415161718191a1b1c1d1e1f")))

(deftest experiments
  (let [result (jwe/encode {:foo :bar} {:key secret})]
    (println result)))
