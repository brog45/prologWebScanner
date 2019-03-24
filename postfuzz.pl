:- use_module(library(http/http_client), [http_read_data/3, http_post/4]).
:- use_module(library(http/http_header), [http_read_request/2]).
:- use_module(library(url), [parse_url/2]).

go :-
    File = 'badstore-cartadd.txt',
    file_request_form(File, Request, FormPairs),
    request_to_url(Request, http, Url),
    format('URL: ~w~nFORM: ~q~n', [Url, FormPairs]),
    fuzz_loop(Url, FormPairs).

fuzz_loop(Url, FormPairs) :- 
    url_form_parameter_vulnerable(Url, FormPairs, ParameterName, Vulnerability), 
    format('Possible ~w vulnerability in form parameter ~q~n', [Vulnerability, ParameterName]),
    fail.
fuzz_loop(_,_).

file_request_form(File, Request, FormPairs) :-
    setup_call_cleanup(open(File, read, Fd, []),
        stream_request_form(Fd, Request, FormPairs),
        close(Fd)).

stream_request_form(Stream, Request, FormPairs) :-
    http_read_request(Stream, Request), 
    http_read_data(Request, FormPairs, []).

request_to_url(Request, Protocol, Url) :-
    % with query parameters in the URL
    subset([host(Host), path(Path), search(Search)], Request), 
    !, parse_url(Url, [protocol(Protocol), host(Host), path(Path), search(Search)]).
request_to_url(Request, Protocol, Url) :-
    % without query parameters
    subset([host(Host), path(Path)], Request), 
    !, parse_url(Url, [protocol(Protocol), host(Host), path(Path)]).

url_form_parameter_vulnerable(Url, FormPairs, ParameterName, Vulnerability) :-
    proxy(Options), 
    vulnerability_spike(Vulnerability, Spike),
    select(ParameterName=_, FormPairs, ParameterName=Spike, SpikedFormPairs),
    http_post(Url, form(SpikedFormPairs), Reply, Options),
    vulnerability_tell(Vulnerability, Tell),
    sub_atom(Reply, _, _, _, Tell).

vulnerability_spike(xss, 'fd<xss>sa').
vulnerability_spike(sqli, 'fd\'sa').
vulnerability_tell(xss, XssTell) :- vulnerability_spike(xss, XssTell).
vulnerability_tell(sqli, 'error in your SQL syntax').

proxy([proxy(Host:Port)]) :- 
    getenv(http_proxy, Url), 
    parse_url(Url, UrlAttributes), 
    memberchk(host(Host), UrlAttributes), 
    memberchk(port(Port), UrlAttributes), 
    !.
proxy([]).
