;;; differential.el --- Answer pyposlib's differential tasks with poslib  -*- lexical-binding: t -*-

;; Copyright (C) 2026 Chris Gough
;; SPDX-License-Identifier: GPL-3.0-or-later

;; emacs -Q --batch -L POSLIB/lisp -l differential.el TASKS OUT
;; Each task is (kind path ...); each answer a CID, a refusal or a report.

(require 'pos-cid)
(require 'pos-ledger)
(require 'pos-seal)

(defun differential-relative (root report)
  "Return REPORT with its absolute paths made relative to ROOT."
  (vconcat
   (mapcar (lambda (entry)
             (mapcar (lambda (pair)
                       (pcase (car pair)
                         ('archive (cons 'archive (file-relative-name (cdr pair) root)))
                         ('checkpoint_writable
                          (cons 'checkpoint_writable
                                (vconcat (mapcar (lambda (f) (file-relative-name f root))
                                                 (cdr pair)))))
                         (_ pair)))
                     entry))
           report)))

(defun differential-answer (task)
  "Return poslib's answer to TASK."
  (let-alist task
    (pcase .kind
      ("cid"
       (let ((pos-cid-chunk-size (or .chunk pos-cid-chunk-size))
             (pos-cid-file-max-links (or .links pos-cid-file-max-links)))
         (condition-case nil
             (if (file-directory-p .path) (pos-cid-directory .path) (pos-cid-file .path))
           (pos-cid-sharding-unsupported "sharding-unsupported")
           (error "error"))))
      ("check"
       (condition-case err
           (let ((root (file-name-as-directory (file-truename .path))))
             (vconcat
              (mapcar (lambda (entry)
                        (mapcar (lambda (pair)
                                  (pcase (car pair)
                                    ('archive (cons 'archive (file-relative-name (cdr pair) root)))
                                    ('checkpoint_writable
                                     (cons 'checkpoint_writable
                                           (vconcat (mapcar (lambda (f) (file-relative-name f root))
                                                            (cdr pair)))))
                                    (_ pair)))
                                entry))
                      (pos-ledger-check .path))))
         (pos-ledger-refused (concat "refused:" (symbol-name (cadr err))))))
      ("seal"
       (condition-case err
           (let* ((root (file-name-as-directory (file-truename .path)))
                  (plan (pos-seal-plan (expand-file-name .source root)
                                       (expand-file-name .destination root) .ledger_id))
                  (result (pos-seal-apply plan (pos-ledger--sha (pos-ledger-json plan)))))
             `((plan . ,(mapcar (lambda (pair)
                                  (if (memq (car pair) '(source destination archive ledger))
                                      (cons (car pair) (file-relative-name (cdr pair) root))
                                    pair))
                                plan))
               (event . ,(decode-coding-string (pos-ledger--read (car result)) 'utf-8))
               (report . ,(differential-relative root (pos-ledger-check root)))))
         (pos-ledger-refused (concat "refused:" (symbol-name (cadr err)))))))))

(let* ((tasks (with-temp-buffer
                (insert-file-contents (car command-line-args-left))
                (json-parse-buffer :object-type 'alist :null-object :null)))
       (answers (vconcat (mapcar #'differential-answer tasks))))
  (let ((coding-system-for-write 'binary))
    (with-temp-file (cadr command-line-args-left)
      (set-buffer-multibyte nil)
      (insert (pos-ledger-json answers)))))
