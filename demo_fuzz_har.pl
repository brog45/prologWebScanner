% demo_fuzz_har.pl: demonstrate fuzzing GET and POST requests saved to a HAR file
%
% The file firefox.har contains samples of requests to the badstore website at address 
% 192.168.56.101. The badstore VM is available for download from vulnhub.com. If you 
% wish to run this script with those samples, you will need to download badstore and 
% configure it to run at that address. I followed the setup instructions in Chapter 2 
% of "Gray Hat C#" by Brandon Perry.
%
% To run this script use this command at the shell prompt: 
%   $ swipl -s demo_fuzz_har.pl
%
% To use an HTTP proxy like BurpSuite or Fiddler, set the environment variable http_proxy: 
%   $ env http_proxy=http://localhost:8080 swipl -s demo_fuzz_har.pl

:- initialization(main).
:- initialization(halt).

% system libraries
:- use_module(library(http/json)).

% modules
:- use_module(webfuzz).

main :-
    fuzz_from_har('firefox.har').

% only fuzz GETs with query parameters and POSTs
in_scope(get, Url) :-
    parse_url(Url, Attributes),
    memberchk(search([_|_]), Attributes).
in_scope(post, _).

fuzz_from_har(File) :-
    format('--- Fuzzing from HAR File: ~w ---~n', [File]),
    har_request(File, Request), 
    request_url_method_form(Request, Url, Method, FormPairs),
    in_scope(Method, Url),
    format('URL: ~w~nMETHOD: ~w~nFORM: ~q~n', [Url, Method, FormPairs]),
    fuzz_loop(Method, Url, FormPairs), 
    check_csrf(Request, Method, FormPairs),
    nl,
    fail.
fuzz_from_har(_).
    
har_request(File, Request) :-
    har_json(File, JsonDict),
    JsonDict :< _{log: Log},
    _{entries:Entries} :< Log,
    member(Entry, Entries),
    _{request:Request} :< Entry.

har_json(File, JsonDict) :-
    setup_call_cleanup(open(File, read, Fd, []),
        json_read_dict(Fd, JsonDict), 
        close(Fd)).

request_url_method_form(Request, Url, Method, Form) :-
    _{url:Url, method:MethodString} :< Request,
    method_atom(MethodString, Method),
    request_method_form(Request, Method, Form).

method_atom("GET", get).
method_atom("POST", post).

request_method_form(_, get, []).
request_method_form(Request, post, FormPairs) :-
    _{postData:PostData} :< Request,
    _{mimeType:MimeType, params:ParamList} :< PostData,
    MimeType = "application/x-www-form-urlencoded",
    maplist(param_dict_to_pair, ParamList, FormPairs).

param_dict_to_pair(Dict, Name=Value) :-
    _{name:Name, value:Value} :< Dict.

fuzz_loop(Method, Url, FormPairs) :- 
    url_parameter_vulnerable(Method, Url, FormPairs, ParameterName, Vulnerability), 
    format('* Possible ~w vulnerability in query parameter ~q~n', [Vulnerability, ParameterName]),
    fail.
fuzz_loop(post, Url, FormPairs) :- 
    url_form_parameter_vulnerable(Url, FormPairs, ParameterName, Vulnerability), 
    format('* Possible ~w vulnerability in form parameter ~q~n', [Vulnerability, ParameterName]),
    fail.
fuzz_loop(_,_,_).

% If a GET request takes action, it can be vulnerable to CSRF, but I don't know how to detect that.
check_csrf(_, get, _).
check_csrf(Request, post, FormPairs) :-
    \+ csrf_protected(Request, post, FormPairs),
    format('* Possible csrf vulnerability~n').

csrf_protected(Request, post, FormPairs) :-
    % very early ASP.NET MVC, circa 2008
    request_cookies(Request, CookiePairs),
    memberchk("__RequestVerificationToken"=Value, FormPairs),
    memberchk("__RequestVerificationToken"=Value, CookiePairs).
csrf_protected(Request, post, FormPairs) :-
    % later ASP.NET MVC
    request_cookies(Request, CookiePairs),
    memberchk("__RequestVerificationToken"=_, FormPairs),
    % there is a cookie with a name that starts with '__RequestVerificationToken_'
    member(Name=_, CookiePairs),
    sub_string(Name, 0, _, _, '__RequestVerificationToken_').

request_cookies(Request, CookiePairs) :-
    _{cookies:CookieDictList} :< Request,
    maplist(param_dict_to_pair, CookieDictList, CookiePairs).
