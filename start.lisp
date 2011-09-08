(in-package :cl-user)

(unless (find-package "QUICKLISP")
    (load "~/quicklisp/setup"))

(defvar *source-directory*
  (make-pathname :name "source" :type nil
		 :defaults (or *load-pathname* *default-pathname-defaults*))
  "The directory that holds the cl-crypto source files, which is assumed
   to be the same directory that this file is being loaded from.")

(defun add-to-registry (&rest paths)
  (dolist (path paths)
    (setf asdf:*central-registry*
	  (adjoin (truename (merge-pathnames path *source-directory*))
		  asdf:*central-registry*
		  :test #'equal))))

(let ((systems-wildcard
       (merge-pathnames
	(make-pathname :directory "systems" :name :wild :type :wild)
	*source-directory*)))
  (apply 'add-to-registry
	 (directory systems-wildcard :directories t :files nil))
  (add-to-registry *source-directory*))

(defun reload ()
  (ql:quickload "cl-crypto" :verbose t))

(defun clc ()
  (let ((set-package (ignore-errors (find-symbol "SET-PACKAGE" :swank))))
    (when set-package
      (funcall set-package :cl-crypto))))


(reload)

(clc)




