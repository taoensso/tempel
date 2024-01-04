(defproject com.taoensso/tempel "1.0.0-alpha1"
  :author "Peter Taoussanis <https://www.taoensso.com>"
  :description "Data security framework for Clojure"
  :url "https://github.com/taoensso/tempel"

  :license
  {:name "Eclipse Public License - v 1.0"
   :url  "https://www.eclipse.org/legal/epl-v10.html"}

  :dependencies
  [[com.taoensso/encore "3.76.0"]]

  :profiles
  {;; :default [:base :system :user :provided :dev]
   :provided {:dependencies [[org.clojure/clojure "1.11.1"]]}
   :c1.11    {:dependencies [[org.clojure/clojure "1.11.1"]]}
   :c1.10    {:dependencies [[org.clojure/clojure "1.10.1"]]}
   :c1.9     {:dependencies [[org.clojure/clojure "1.9.0"]]}

   :test
   {:jvm-opts ["-Dtaoensso.elide-deprecated=true"]
    :global-vars
    {*warn-on-reflection* true
     *assert*             true
     *unchecked-math*     false #_:warn-on-boxed}

    :dependencies
    [[org.clojure/test.check "1.1.1"]]}

   :graal-tests
   {:dependencies [[org.clojure/clojure "1.11.1"]
                   [com.github.clj-easy/graal-build-time "1.0.5"]]
    :main taoensso.graal-tests
    :aot [taoensso.graal-tests]
    :uberjar-name "graal-tests.jar"}

   :dev
   [:c1.11 :test
    {:jvm-opts ["-server"]
     :plugins
     [[lein-pprint  "1.3.2"]
      [lein-ancient "0.7.0"]
      [com.taoensso.forks/lein-codox "0.10.10"]]

     :codox
     {:language #{:clojure #_:clojurescript}
      :base-language :clojure}}]}

  :test-paths ["test" #_"src"]

  :aliases
  {"start-dev"     ["with-profile" "+dev" "repl" ":headless"]
   ;; "build-once" ["do" ["clean"] ["cljsbuild" "once"]]
   "deploy-lib"    ["do" #_["build-once"] ["deploy" "clojars"] ["install"]]

   "test-clj"     ["with-profile" "+c1.11:+c1.10:+c1.9" "test"]
   ;; "test-cljs" ["with-profile" "+test" "cljsbuild"   "test"]
   "test-all"     ["do" ["clean"] ["test-clj"] #_["test-cljs"]]})
