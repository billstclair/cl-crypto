(in-package :cl-crypto)

;;;
;;; Random number generation
;;;


(defparameter +linux-urandom-dev+ #P"/dev/urandom")
(defvar *random-byte-stream*
  #-windows nil
  #+windows (make-random-stream))

;; Call initialize-windows-crypto-library when
;; a saved application starts.
;; See ffi.lisp for *crypt-context* and advapi32 definitions.
(defun initialize-windows-crypto-library ()
  #+windows
  (progn
    (setf *crypt-context* nil)
    (cffi:load-foreign-library 'advapi32)))

(defmacro with-random-byte-stream (&body body)
  (let ((thunk (gensym)))
    `(flet ((,thunk () ,@body))
       (declare (dynamic-extent #',thunk))
       (call-with-random-byte-stream #',thunk))))

(defun call-with-random-byte-stream (thunk)
  (if *random-byte-stream*
      (funcall thunk)
      #-windows
      (with-open-file (*random-byte-stream*
                       +linux-urandom-dev+
                       :element-type '(unsigned-byte 8))
        (funcall thunk))
      #+windows (funcall thunk)))

(defun get-random-bits (num-bits)
  (with-random-byte-stream ()
    (let ((num-bytes (ceiling num-bits 8))
          (result 0)
          (in *random-byte-stream*))
      (dotimes (i num-bytes)
        (setq result (logior result (ash (read-byte in) (* i 8)))))
      result)))

(defvar *show-random-integer-progress-p* nil)

(defun random-integer (ceiling &optional
                       (progress-p *show-random-integer-progress-p*))
  (when progress-p (princ "."))
  (let* ((nbits (* 8 (ceiling (integer-length (1+ ceiling)) 8)))
         (x (get-random-bits nbits))
         (n (ash 1 nbits)))
    (floor (* x ceiling) n)))

(defun random-string (length)
  (let ((res (make-string length)))
    (with-random-byte-stream
      (let ((in *random-byte-stream*))
        (dotimes (i length)
          (setf (aref res i) (code-char (read-byte in))))))
    res))
               
;;
;; Returns a random number x such that:
;;	floor <= x <= ceiling
;;
(defun get-ranged-random-num (floor ceiling)
  (+ floor (random-integer (- ceiling floor))))
