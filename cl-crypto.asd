; -*- mode: lisp -*-
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
     (:file "macros")
     (:file "aes16")
     (:file "sha1")
     (:file "strings")))))

