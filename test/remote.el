;;; remote.el --- poslib's client against a keeper, for test_remote.py  -*- lexical-binding: t -*-

;; Copyright (C) 2026 Chris Gough

;; Author: Chris Gough
;; SPDX-License-Identifier: GPL-3.0-or-later

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; emacs -Q --batch -L POSLIB/lisp -l remote.el REQUEST ANSWER
;;
;; REQUEST holds a keeper's url and token and one event to append, with
;; its files.  poslib's own HTTP exchange makes each call, and ANSWER
;; gets what came back, a refusal as its kind.

;;; Code:

(require 'pos-remote)

(defun remote-attempt (operation)
  "Return what OPERATION returns, or its refusal's kind."
  (condition-case err
      (funcall operation)
    (pos-ledger-refused `((refused . ,(symbol-name (cadr err)))))))

(let* ((request (with-temp-buffer
                  (insert-file-contents (car command-line-args-left))
                  (json-parse-buffer :object-type 'alist :null-object :null)))
       (text (lambda (bytes) (decode-coding-string bytes 'utf-8)))
       (answers
        (let-alist request
          (let ((keeper (pos-remote-http-create :url .url :token .token))
                (stranger (pos-remote-http-create :url .url :token "not-the-token")))
            `((appended . ,(remote-attempt
                            (lambda ()
                              (pos-remote-append
                               keeper .name (encode-coding-string .event 'utf-8 t)
                               (mapcar (lambda (file)
                                         (cons (symbol-name (car file))
                                               (encode-coding-string (cdr file) 'utf-8 t)))
                                       .files)
                               .claims))))
              (described . ,(remote-attempt (lambda () (pos-remote-describe keeper))))
              (event . ,(remote-attempt
                         (lambda () (funcall text (pos-remote-event keeper 1)))))
              (read . ,(remote-attempt
                        (lambda () (funcall text (pos-remote-read keeper .cid .path)))))
              (absent . ,(remote-attempt (lambda () (pos-remote-event keeper 2))))
              (stranger . ,(remote-attempt (lambda () (pos-remote-describe stranger)))))))))
  (let ((coding-system-for-write 'binary))
    (with-temp-file (cadr command-line-args-left)
      (set-buffer-multibyte nil)
      (insert (pos-ledger-json answers)))))

;;; remote.el ends here
