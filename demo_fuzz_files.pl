% demo_fuzz_files.pl: demonstrate fuzzing GET and POST requests saved to text files
%
% The text files get.txt and post.txt contain samples of requests to the badstore website 
% at address 192.168.56.101. The badstore VM is available for download from vulnhub.com. 
% If you wish to run this script with those samples, you will need to download badstore 
% and configure it to run at that address. I followed the setup instructions in Chapter 2 
% of "Gray Hat C#" by Brandon Perry.
%
% To run this script use this command at the shell prompt: 
%   $ swipl -s demo_fuzz_files.pl
%
% To use an HTTP proxy like BurpSuite or Fiddler, set the environment variable http_proxy: 
%   $ env http_proxy=http://localhost:8080 swipl -s demo_fuzz_files.pl

:- initialization(main).
:- initialization(halt).

% system libraries
:- use_module(library(http/http_client), [http_read_data/3]).
:- use_module(library(http/http_header), [http_read_request/2]).
:- use_module(library(url), [parse_url/2]).

% modules
:- use_module(webfuzz).

main :-
    fuzz_from_file('get.txt'),
    fuzz_from_file('post.txt').

fuzz_from_file(File) :-
    format('--- Fuzzing from File: ~w ---~n', [File]),
    file_request_form(File, Request, FormPairs),
    request_to_url(Request, http, Url),
    memberchk(method(Method), Request),
    format('URL: ~w~nMETHOD: ~w~nFORM: ~q~n', [Url, Method, FormPairs]),
    !, fuzz_loop(Method, Url, FormPairs), 
    nl.

file_request_form(File, Request, FormPairs) :-
    setup_call_cleanup(open(File, read, Fd, []),
        stream_request_form(Fd, Request, FormPairs),
        close(Fd)).

stream_request_form(Stream, Request, FormPairs) :-
    http_read_request(Stream, Request), 
    http_read_data(Request, FormPairsTmp, []),
    (   FormPairsTmp = [_,_]
    ->  FormPairs = FormPairsTmp
    ;   FormPairs = []
    ).

request_to_url(Request, Protocol, Url) :-
    % with query parameters in the URL
    subset([host(Host), path(Path), search(Search)], Request), 
    !, parse_url(Url, [protocol(Protocol), host(Host), path(Path), search(Search)]).
request_to_url(Request, Protocol, Url) :-
    % without query parameters
    subset([host(Host), path(Path)], Request), 
    !, parse_url(Url, [protocol(Protocol), host(Host), path(Path)]).

fuzz_loop(Method, Url, FormPairs) :- 
    url_parameter_vulnerable(Method, Url, FormPairs, ParameterName, Vulnerability), 
    format('Possible ~w vulnerability in query parameter ~q~n', [Vulnerability, ParameterName]),
    fail.
fuzz_loop(post, Url, FormPairs) :- 
    url_form_parameter_vulnerable(Url, FormPairs, ParameterName, Vulnerability), 
    format('Possible ~w vulnerability in form parameter ~q~n', [Vulnerability, ParameterName]),
    fail.
fuzz_loop(_,_,_).
