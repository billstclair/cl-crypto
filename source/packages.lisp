(in-package :common-lisp-user)

(defpackage cl-crypto
  (:use common-lisp)
  (:export
   ;; rsa.lisp
   ;; RSA interface
   rsa-gen
   rsa-encrypt
   rsa-decrypt
   ;; RSA tests
   rsa-self-test
   ;; aes16.lisp
   ;; AES interface
   aes-expand-key
   aes-encrypt
   aes-decrypt
   ;; AES Tests
   aes-self-test
   aes-get-speed
   aes-get-avg-speed
   ;; sha1.lisp
   ;; strings.lisp
   sha1
   hmac-sha1
   pbkdf2
   generate-iv
   iv-to-base64
   base64-to-iv
   passphrase-to-aes-key
   aes-encrypt-string
   aes-decrypt-to-string
   aes-string-encryption-test
   ;;utility.lisp
   hex-string-from-word-list
   ;;ffi.lisp
   #+windows make-random-stream
   ;;random.lisp
   initialize-windows-crypto-library
   with-random-byte-stream
   random-integer
   random-string
   get-ranged-random-num
   get-random-bits
   ))

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
