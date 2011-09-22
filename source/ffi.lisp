(in-package :cl-crypto)

;;;
;;; FFI for Windows random number generation
;;;

(cffi:define-foreign-library advapi32
  (:windows "advapi32.dll"))

(cffi:defctype dword :ulong)

(cffi:defcfun ("CryptGenRandom" %crypt-gen-random)
    :boolean
  (hProv :pointer)
  (dwLen dword)
  (pbBuffer :pointer))

(cffi:defcfun ("CryptAcquireContextW" %crypt-acquire-context)
    :boolean
  (phProv :pointer)			;output
  (pszContainer :pointer)		;usually NULL
  (pszProvider :pointer)		;usually NULL
  (dwProvType dword)
  (dwFlags dword))

;; From wincrypt.h
(defconstant $PROV-RSA-FULL 1)
(defconstant $CRYPT-VERIFYCONTEXT 0)

(defun crypt-acquire-default-context ()
  (cffi:with-foreign-object (phProv :pointer)
    (unless (%crypt-acquire-context
	     phProv
	     (cffi:null-pointer)
	     (cffi:null-pointer)
	     $PROV-RSA-FULL
	     $CRYPT-VERIFYCONTEXT)
      (error "Can't acquire context"))
    (cffi:mem-ref phProv :pointer)))

(defvar *crypt-context* nil)

(defun get-crypt-context ()
  (or *crypt-context*
      (setf *crypt-context*
	    (crypt-acquire-default-context))))

(defun crypt-gen-random (len &optional
			 (res (make-array len :element-type 'uint-8)))
  (cffi:with-foreign-pointer (phBuffer len)
    (%crypt-gen-random (get-crypt-context) len phBuffer)
    (dotimes (i len)
      (setf (aref res i) (cffi:mem-ref phBuffer :unsigned-char i))))
  res)

(defconstant $CRYPT-STREAM-BUFFER-SIZE 256)

(defclass random-stream (trivial-gray-streams:trivial-gray-stream-mixin)
  ((buf :initform (make-array $CRYPT-STREAM-BUFFER-SIZE
			      :element-type 'uint-8)
	:accessor buf-of)
   (ptr :initform nil
	:accessor ptr-of)))

(defun make-random-stream ()
  (make-instance 'random-stream))

(defvar *gen-random-lock*
  (bordeaux-threads:make-lock "*gen-random-lock*"))

(defmethod trivial-gray-streams:stream-read-byte ((stream random-stream))
  (bordeaux-threads:with-lock-held (*gen-random-lock*)
    (let* ((ptr (ptr-of stream))
	   (buf (buf-of stream))
	   (len (length buf)))
      (when (or (null ptr) (>= ptr len))
	(crypt-gen-random len buf)
	(setf ptr 0))
      (prog1
	  (aref buf ptr)
	(setf (ptr-of stream) (1+ ptr))))))

(defmethod trivial-gray-streams:stream-read-char ((stream random-stream))
  (code-char (read-byte stream)))

(defmethod close ((stream random-stream) &key abort)
  (declare (ignore abort))
  nil)