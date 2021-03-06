(defproject buddy/buddy-sign "0.4.1"
  :description "High level message signing"
  :url "https://github.com/funcool/buddy-sign"
  :license {:name "BSD (2-Clause)"
            :url "http://opensource.org/licenses/BSD-2-Clause"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [com.taoensso/nippy "2.8.0"]
                 [buddy/buddy-core "0.4.2"]
                 [cats "0.3.4"]
                 [clj-time "0.9.0"]
                 [cheshire "5.4.0"]]
  :source-paths ["src"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :test-paths ["test"])
