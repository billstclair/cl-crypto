;;;; -*- mode: lisp -*-

(in-package #:cl-user)

(asdf:defsystem :cl-crypto
  :description "Pure Lisp Cryptography"
  :author "Mr. Bug <mrbug@rayservers.net>"
  :version "0.1"
  :license "Apache"
  :depends-on (cl-base64 flexi-streams)
  :components
  ((:module source
    :serial t
    :components
    ((:file "packages")
     (:file "types")
     (:file "utility")
     (:file "math")
     (:file "random")
     (:file "small-primes")
     (:file "prime")
     (:file "rsa")
     (:file "rsa-padding")
     (:file "aes16")
     (:file "sha1")
     (:file "strings")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Copyright 2010 TSC AG, Postfach 73, CH 6314 Unterageri, Switzerland
;;;
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at
;;;
;;;     http://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions
;;; and limitations under the License.
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
