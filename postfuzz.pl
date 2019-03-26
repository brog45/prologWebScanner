:- module(postfuzz,[url_form_parameter_vulnerable/4]).

:- use_module(library(http/http_client), [http_read_data/3, http_post/4]).

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
