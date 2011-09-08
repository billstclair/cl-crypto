;;; =============================================================
;;; High-level string-based functions
;;; Author: Bill St. Clair
;;; =============================================================
;;; Notes:
;;; ---
;;; Eric O'Connor, 8/18/2011
;;;   Added an explicit preprocessor
;;;   Uses 32 bit integers
;;;   Added hmac-sha1 & pbkdf2
;;; =============================================================

(in-package :cl-crypto)

(defun make-preprocessor (words &key (blocks 0) byte-length)
  (let ((pos 0) (len (length words))
        (state :begin))
    (lambda (&aux (m (make-array 16
                                 :element-type 'uint-32
                                 :fill-pointer 0)))
      (unless (eq state :done)
        (dotimes (i (min 16 (- len pos)))
          (vector-push (aref words (+ pos i)) m))
        (when (< (length m) 16)
          (when (eq state :begin)
            (let ((byte-pos
                   (and byte-length (- (* len 4) byte-length)))
                  (cur (1- (length m))))
              (if (and byte-pos (plusp byte-pos))
                  (setf (aref m cur)
                        (logior (aref m cur) (ash 1 (1- (* byte-pos 8)))))
                  (vector-push #x80000000 m)))
            (setf state :pad))
          (let ((c (length m)))
            (dotimes (i (- 16 (length m)))
              (vector-push 0 m))
            (when (<= c 14)
              (setf state :done)
              (let ((blen (+ (or (and byte-length (* byte-length 8))
                                 (* len 32))
                             (* blocks 512))))
                (setf (aref m 14) (ldb (byte 32 32) blen)
                      (aref m 15) (ldb (byte 32 0) blen))))))
        (incf pos 16)
        m))))

(defun return-state (state res-type)
  (ecase res-type
    (:words
     (map '(vector uint-32) #'identity
          state))
    (:hex (hex-string-from-word-list state))
    (:bytes (hex-vector-from-word-list state))
    (:string
     (let ((res (make-string 20))
           (i 0))
       (dolist (x state)
         (setf (aref res i)
               (code-char (ldb (byte 8 24) x))
               (aref res (incf i))
               (code-char (ldb (byte 8 16) x))
               (aref res (incf i))
               (code-char (ldb (byte 8 8) x))
               (aref res (incf i))
               (code-char (ldb (byte 8 0) x)))
         (incf i))
       res))))

(defun sha1 (string &key (res-type :hex) initial-state (blocks 0)
             byte-length)
  (declare (optimize (speed 3) (space 0)))
  "Return the sha1 hash of STRING.
    Return a string of hex chars if res-type is :hex, the default,
    a byte-array if res-type is :bytes,
    or a string with 8-bit character values if res-type is :string."
  (multiple-value-bind (octets length)
      (ensure-words string)
    (declare (type (vector uint-32) octets))
    (let ((state (or initial-state (sha1-get-initial-state)))
          (preprocessor (make-preprocessor
                         octets
                         :blocks blocks
                         :byte-length (or byte-length
                                          length))))
      (loop
         for x = (the (or (vector uint-32) null)
                   (funcall preprocessor))
         while x do
           (sha1-process-message state x))
      (return-state (state-of state) res-type))))

(defun hmac-sha1 (key string &key (res-type :hex)
                  byte-length)
  (declare (optimize (speed 3) (space 0)))
  (let ((pad (make-array 16 :element-type 'uint-32))
        (istate (sha1-get-initial-state))
        (key-words (ensure-words key)))
    (declare (type (vector uint-32) key-words pad))
    (when (> (length key-words) 16)
      (setf key-words (sha1 key-words
                            :res-type :words)))
    (dotimes (x 16)
      (setf (aref pad x)
            (if (< x (length key-words))
                (logxor (aref key-words x) #x36363636) #x36363636)))
    (sha1-process-message istate pad)
    (let ((hash (sha1 string
                      :res-type :words
                      :initial-state istate
                      :blocks 1
                      :byte-length byte-length))
          (ostate (sha1-get-initial-state)))
      (declare (type (vector uint-32) hash))
      (dotimes (x 16)
        (setf (aref pad x)
              (if (< x (length key-words))
                  (logxor (aref key-words x) #x5c5c5c5c) #x5c5c5c5c)))
      (sha1-process-message ostate pad)
      (sha1 hash :res-type res-type :initial-state ostate
            :blocks 1 :byte-length 20))))

(defun pbkdf2 (password salt iter key-bytes)
  (declare (optimize (speed 3) (space 0)))
  (let ((pwords (ensure-words password)))
    (declare (type (vector uint-32) pwords))
    (multiple-value-bind (swords saltlen)
        (ensure-words salt)
      (declare (type (vector uint-32) swords))
      (let ((saltvec (make-array (1+ (length swords))
                                 :element-type 'uint-32)))
        (declare (type (vector uint-32) saltvec))
        (flet ((f (i)
                 (setf (subseq saltvec 0 (length swords)) swords)
                 (setf (aref saltvec (length swords)) i)
                 (let* ((u (hmac-sha1 pwords saltvec
                                      :res-type :words
                                      :byte-length (+ 4 saltlen)))
                        (last u))
                   (declare (type (vector uint-32) u last))
                   (dotimes (n (1- iter))
                     (setf last (hmac-sha1 pwords last
                                           :res-type :words))
                     (dotimes (j 5)
                       (setf (aref u j)
                             (logxor (aref u j)
                                     (aref last j)))))
                   u)))
          (let* ((keylen (ceiling key-bytes 20))
                 (collect (make-array (* keylen 5)
                                      :element-type 'uint-32)))
            (dotimes (m keylen)
              (setf (subseq collect (* m 5) (* (1+ m) 5)) (f (1+ m))))
            (subseq collect 0 (ceiling key-bytes 4))))))))

(defun generate-iv (&optional (num-bytes 16))
  "Generate an Initialization Vector array for block chaining"
  (let* ((result (make-array num-bytes :element-type 'uint-8)))
    (with-random-byte-stream
      (let ((s *random-byte-stream*))
        (dotimes (i num-bytes)
          (setf (aref result i) (read-byte s)))))
    result))

(defun iv-to-base64 (iv)
  (cl-base64:usb8-array-to-base64-string iv))

(defun base64-to-iv (string)
  (cl-base64:base64-string-to-usb8-array string))

(defun passphrase-to-aes-key (passphrase &optional (bits 128))
  (check-type bits (member 128 192 256))
  (cond ((typep passphrase 'aes-key) passphrase)
        ((typep passphrase '(array uint-8))
         (assert (member (length passphrase) '(16 24 32)))
         (aes-expand-key passphrase))
        (t (let* ((bytes (/ bits 8))
                  (res (make-array bytes :element-type 'uint-8))
                  (len (length passphrase))
                  (half-len (if (eql bits 128) len (ceiling len 2)))
                  (str1 (subseq passphrase 0 half-len))
                  (str2 (and (< half-len len)
                                   (subseq passphrase half-len)))
                  (hash1 (sha1 str1 :res-type :bytes))
                  (hash2 (and str2 (sha1 str2 :res-type :bytes)))
                  (hashlen (length hash1))
                  (j 0))
             (dotimes (i bytes)
               (setf (aref res i)
                     (logxor (aref res i) (aref hash1 j)))
               (setf j (mod (1+ j) hashlen))
               (when (eql j 0)
                 (setf hash1 hash2)))
             (aes-expand-key res)))))

(defun aes-encrypt-string (string passphrase &key
                           (bits 128)
                           (blocking-method :cbc)
                           (iv (generate-iv))
                           keys
                           (columns 0))
  "Encrypt STRING to the given PASSPHRASE, using AES of the given number of BITS.
   BITS can be 128, 192, or 256.
   BLOCKING-METHOD can be :CBC, the default.
   IV is an initial vector, which will be generated if not passed.
   If KEYS is included, it should be an AES-KEY instance as returned by
     PASSPHRASE-TO-AES-KEY or AES-EXPAND-KEY. It will be used instead of PASSPHRASE.
   COLUMNS is the number of columns for the resulting base64 string.
   COLUMNS defaults to 0, adds no newlines to the base64 string.
   If COLUMNS is passes as NIL, returns a uint-8 array instead of converting to base64.
   Returns 2 values:
     1) The encrypted base64 string or array
     2) iv"
  (check-type bits (member 128 192 256))
  (assert (eq blocking-method :cbc)
          nil
          "Unknown blocking method, only :cbc supported: ~s" blocking-method)
  (assert (equal (length iv) 16))
  (let* ((in (make-array 16 :element-type 'uint-8))
         (out (make-array 16 :element-type 'uint-8))
         (octets (flexi-streams:string-to-octets string :external-format :utf-8))
         (size (length octets))
         (blocks (ceiling size 16))
         (total-bytes (* blocks 16))
         (res (make-array total-bytes :element-type 'uint-8))
         (keys (or keys (passphrase-to-aes-key passphrase bits)))
         (iv-buf (copy-seq iv))
         (j 0)
         (k 0))
    (declare (dynamic-extent in out res))
    (dotimes (i size)
      (setf (aref in j)
            (logxor (aref octets i) (aref iv-buf j)))
      (when (eql 16 (incf j))
        (aes-encrypt keys in :out out)
        (dotimes (j 16)
          (setf (aref res k)
                (setf (aref iv-buf j) (aref out j)))
          (incf k))
        (setf j 0)))
    (when (and (eql j 0)
               (> k 0)
               (member (aref octets (1- k)) '(#x80 0)))
      ;; May need an extra block to distinguish final byte of #x80 or 0
      (unless (and (eql 0 (aref octets (1- k)))
                   (loop for i from (- k 2) downto (- k 16)
                      for o = (aref octets k)
                      do
                        (when (eql o #x40) (return nil))
                        (unless (eql o 0) (return t))))
        (incf total-bytes 16)
        (let ((new-res (make-array total-bytes :element-type 'uint-8)))
          (dotimes (i (length res))
            (setf (aref new-res i) (aref res i)))
          (setf res new-res))))
    (unless (eql k total-bytes)
      (let ((pad #x40))
        (loop
           (when (eql j 16) (return))
           (setf (aref in j)
                 (if pad (logxor pad (aref iv-buf j)) (aref iv-buf j))
                 pad nil)
           (incf j)))
      (aes-encrypt keys in :out out)
      (dotimes (j 16)
        (setf (aref res k) (aref out j))
        (incf k)))
    (values
     (if columns
         (cl-base64:usb8-array-to-base64-string res :columns columns)
         (copy-seq res))
     iv)))

(defun aes-decrypt-to-string (string passphrase &key
                              (bits 128)
                              (blocking-method :cbc)
                              iv
                              keys)
  "Decrypt AES-ENCRYPT-TO-STRING result with the PASSPHRASE, using AES of the
      given number of BITS.
    BITS can be 128, 192, or 256.
    BLOCKING-METHOD can be :CBC, the default.
    IV must be the same initial vector returned as the second value of
      AES-ENCRYPT-TO-STRING.
    If KEYS is included, it should be an AES-KEY instance as returned by
      PASSPHRASE-TO-AES-KEY or AES-EXPAND-KEY. It will be used instead of PASSPHRASE."
  (check-type bits (member 128 192 256))
  (assert (eq blocking-method :cbc)
          nil
          "Unknown blocking method, only :cbc supported: ~s" blocking-method)
  (when (stringp iv)
    (setf iv (cl-base64:base64-string-to-usb8-array iv)))
  (assert (equal (length iv) 16))
  (when (eql 0 (length string))
    (return-from aes-decrypt-to-string ""))
  (let* ((in (make-array 16 :element-type 'uint-8))
         (out (make-array 16 :element-type 'uint-8))
         (octets (if (stringp string)
                     (cl-base64:base64-string-to-usb8-array string)
                     (progn
                       (check-type string (array uint-8))
                       string)))
         (size (length octets))
         (res (make-array size :element-type 'uint-8))
         (keys (or keys (passphrase-to-aes-key passphrase bits)))
         (iv-buf (copy-seq iv))
         (j 0)
         (k 0))
    (assert (eql 0 (mod size 16)))
    (dotimes (i size)
      (setf (aref in j) (aref octets i))
      (incf j)
      (when (eql j 16)
        (setf j 0)
        (aes-decrypt keys in :out out)
        (dotimes (j 16)
          (setf (aref res k) (logxor (aref out j) (aref iv-buf j))
                (aref iv-buf j) (aref octets k))
          (incf k))))
    (dotimes (j 16)
      (decf k)
      (let ((x (aref res k)))
        (when (eql x #x40)
          (setf size k)
          (return))
        (unless (eql x 0)
          (return))))
    (flexi-streams:octets-to-string res :external-format :utf-8 :end size)))

(defun aes-string-encryption-test ()
  (let ((string "Four score and seven years ago our forefathers set forth on this continent a new republic, conceived in liberty and dedicated to the proposition that all men are created equal. ")
        (passphrase "A really secret password. Really."))
    (dotimes (i 10)
      (multiple-value-bind (cipher iv)
          (aes-encrypt-string string passphrase :bits 128 :columns 40)
        (assert (equal string
                       (aes-decrypt-to-string
                        cipher passphrase :iv iv :bits 128))
                nil
                "128-bit AES test failed"))
      (multiple-value-bind (cipher iv)
          (aes-encrypt-string string passphrase :bits 192 :columns 40)
        (assert (equal string
                       (aes-decrypt-to-string
                        cipher passphrase :iv iv :bits 192))
                nil
                "192-bit AES test failed"))
      (multiple-value-bind (cipher iv)
          (aes-encrypt-string string passphrase :bits 256 :columns 40)
        (assert (equal string
                       (aes-decrypt-to-string
                        cipher passphrase :iv iv :bits 256))
                nil
                "256-bit AES test failed")))))

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
