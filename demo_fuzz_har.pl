% :- initialization(main).
% :- initialization(halt).

:- use_module(library(http/json)).

:- use_module(webfuzz).

main :-
    fuzz_from_har('firefox.har').

fuzz_from_har(File) :-
    format('--- Fuzzing from HAR File: ~w ---~n', [File]),
    har_request(File, Request), 
    request_url_method_form(Request, Url, Method, FormPairs),
    format('URL: ~w~nMETHOD: ~w~nFORM: ~q~n', [Url, Method, FormPairs]),
    fuzz_loop(Method, Url, []).
    
har_request(File, X) :-
    har_json(File, JsonDict),
    JsonDict :< _{log: Log},
    _{entries:Entries} :< Log,
    member(Entry, Entries),
    _{request:X} :< Entry.

har_json(File, JsonDict) :-
    setup_call_cleanup(open(File, read, Fd, []),
    json_read_dict(Fd, JsonDict), 
    close(Fd)).

request_url_method_form(Request, Url, Method, Form) :-
    _{url:Url, method:MethodString} :< Request,
    method_atom(MethodString, Method),
    Form = [],
    !.

method_atom("GET", get).
method_atom("POST", post).

fuzz_loop(Method, Url, FormPairs) :- 
    url_parameter_vulnerable(Method, Url, FormPairs, ParameterName, Vulnerability), 
    format('Possible ~w vulnerability in query parameter ~q~n', [Vulnerability, ParameterName]),
    fail.
fuzz_loop(_,_,_).
