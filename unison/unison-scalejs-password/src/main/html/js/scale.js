/*
Copyright 2015, 2016 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
(function(){
  var app = angular.module('scale',['treeControl']);





    app.controller('ScaleController',['$compile', '$scope','$window','$http',function($compile, $scope, $window, $http){


      this.appIsError = false;
      this.sessionLoaded = false;
      this.config = {};
      this.currentTab = 'home';
      this.displayName = 'No User Loaded';
      this.showModal = false;

      this.modalTitle;
      this.modalMessage;
      this.requestReason = "";







      //Methods
      this.finishLogout = function() {
          window.location = this.config.logoutURL;
      };


      this.saveSingleRequest = function() {
        this.modalMessage = "Setting Password...";
        this.showModal = true;
        $scope.scale.sumbitRequestDisabled = true;
        $scope.scale.sumbitRequestSuccess = false;

        req = {};
        req['password1'] = this.password1;
        req['password2'] = this.password2;

        $http.post('password/submit',req).then(
          function(response) {
            $scope.scale.showModal = false;
            $scope.scale.sumbitRequestDisabled = false;
            $scope.scale.requestReason = "";




            $scope.scale.saveRequestSuccess = true;
            $scope.scale.saveRequestErrors = [];
          },
          function(response) {
            $scope.scale.saveRequestErrors = response.data.errors;
            $scope.scale.showModal = false;
            $scope.scale.sumbitRequestDisabled = false;
            $scope.scale.saveRequestSuccess = false;
          }
        );
      };




      this.isSelectedTab = function(val) {
        return val == this.currentTab;
      };

      this.setSelectedTab = function(val) {
        if (val === 'logout') {
            this.finishLogout();
        } else if (val === 'home') {
          window.location = this.config.homeURL;
        } else {
          this.currentTab = val;
        }



      };

      this.isSessionLoaded = function() {
        return this.sessionLoaded;
      }

      this.setSessionLoadedComplete = function() {
        this.sessionLoaded = true;
        this.sumbitRequestDisabled = false;
        this.requestReason = "";
      }

      this.isMobile = function() {
        var ow = $window.outerWidth;
        var mobile = (ow <= 991);
        return ! mobile;
      };




      angular.element(document).ready(function () {



        $http.get('password/config').then(
          function(response) {

	    	  try {
	          	JSON.parse(JSON.stringify(response.data));
	          } catch (e) {
	          	location.reload(true);
	          }

            $scope.scale.config = response.data.config;
            $scope.scale.displayName = response.data.displayName;

            $scope.scale.setSessionLoadedComplete();
            $scope.scale.appIsError = false;
            //$scope.$apply();



          },
          function(response) {
            $scope.scale.appIsError = true;
            //$scope.$apply();
          }

        );




      });

    }







    ]);

    app.directive('modal', function () {
        return {
          template: '<div class="modal fade">' +
              '<div class="modal-dialog">' +
                '<div class="modal-content">' +
                  '<div class="modal-header">' +
                    '<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>' +
                    '<h4 class="modal-title">{{ title }}</h4>' +
                  '</div>' +
                  '<div class="modal-body" ng-transclude></div>' +
                '</div>' +
              '</div>' +
            '</div>',
          restrict: 'E',
          transclude: true,
          replace:true,
          scope:true,
          link: function postLink(scope, element, attrs) {
            scope.title = attrs.title;

            scope.$watch(attrs.visible, function(value){
              if(value == true)
                $(element).modal('show');
              else
                $(element).modal('hide');
            });

            $(element).on('shown.bs.modal', function(){
              scope.$apply(function(){
                scope.$parent[attrs.visible] = true;
              });
            });

            $(element).on('hidden.bs.modal', function(){
              scope.$apply(function(){
                scope.$parent[attrs.visible] = false;
              });
            });
          }
        };
      });

      app.directive("calendar", function() {
          return {
              restrict: "E",
              templateUrl: "templates/calendar.html",
              scope: {
                  selected: "="
              },
              link: function(scope) {
                  scope.selected = _removeTime(scope.selected || moment());
                  scope.month = scope.selected.clone();

                  var start = scope.selected.clone();
                  start.date(1);
                  _removeTime(start.day(0));

                  _buildMonth(scope, start, scope.month);

                  scope.select = function(day) {
                      scope.selected = day.date;
                  };

                  scope.next = function() {
                      var next = scope.month.clone();
                      _removeTime(next.month(next.month()+1).date(1));
                      scope.month.month(scope.month.month()+1);
                      _buildMonth(scope, next, scope.month);
                  };

                  scope.previous = function() {
                      var previous = scope.month.clone();
                      _removeTime(previous.month(previous.month()-1).date(1));
                      scope.month.month(scope.month.month()-1);
                      _buildMonth(scope, previous, scope.month);
                  };
              }
          };

          function _removeTime(date) {
              return date.day(0).hour(0).minute(0).second(0).millisecond(0);
          }

          function _buildMonth(scope, start, month) {
              scope.weeks = [];
              var done = false, date = start.clone(), monthIndex = date.month(), count = 0;
              while (!done) {
                  scope.weeks.push({ days: _buildWeek(date.clone(), month) });
                  date.add(1, "w");
                  done = count++ > 2 && monthIndex !== date.month();
                  monthIndex = date.month();
              }
          }

          function _buildWeek(date, month) {
              var days = [];
              for (var i = 0; i < 7; i++) {
                  days.push({
                      name: date.format("dd").substring(0, 1),
                      number: date.date(),
                      isCurrentMonth: date.month() === month.month(),
                      isToday: date.isSame(new Date(), "day"),
                      date: date
                  });
                  date = date.clone();
                  date.add(1, "d");
              }
              return days;
          }
      });

})();
