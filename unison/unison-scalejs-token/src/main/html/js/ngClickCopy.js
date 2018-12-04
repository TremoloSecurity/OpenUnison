/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
'use strict';

angular.module('ngClickCopy', [])
.service('ngCopy', ['$window', function ($window) {
	var body = angular.element($window.document.body);
	var textarea = angular.element('<textarea/>');
	textarea.css({
		position: 'fixed',
		opacity: '0'
	});

	return function (toCopy) {
		textarea.val(toCopy);
		body.append(textarea);
		textarea[0].select();

		try {
			var successful = document.execCommand('copy');
			if (!successful) throw successful;
		} catch (err) {
			window.prompt("Copy to clipboard: Ctrl+C, Enter", toCopy);
		}

		textarea.remove();
	}
}])
.directive('ngClickCopy', ['ngCopy', function (ngCopy) {
	return {
		restrict: 'A',
		link: function (scope, element, attrs) {
			element.bind('click', function (e) {
				ngCopy(attrs.ngClickCopy);
			});
		}
	}
}])