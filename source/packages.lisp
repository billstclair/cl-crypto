(in-package :common-lisp-user)

(defpackage cl-crypto
  (:use common-lisp)
  (:export
   ;;; aes16.lisp
   ;; AES interface
   #:aes-expand-key
   #:aes-encrypt
   #:aes-decrypt
   ;; AES Tests
   #:aes-self-test
   #:aes-get-speed
   #:aes-get-avg-speed
   ;; sha1.lisp
   ))



  
