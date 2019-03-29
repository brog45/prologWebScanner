:- module(urlfuzz,[url_parameter_vulnerable/5, url_form_parameter_vulnerable/4]).

:- use_module(library(http/http_client)).

url_form_parameter_vulnerable(Url, FormPairs, ParameterName, Vulnerability) :-
    proxy(Options), 
    vulnerability_spike(Vulnerability, Spike),
    select(ParameterName=_, FormPairs, ParameterName=Spike, SpikedFormPairs),
    http_post(Url, form(SpikedFormPairs), Reply, Options),
    vulnerability_tell(Vulnerability, Tell),
    sub_atom(Reply, _, _, _, Tell).

%!	url_parameter_vulnerable(+Method, +Url, +FormPairs, -Name, -Vulnerability) is nondet
%   Tests Url for vulnerable parameters and succeeds when parameter named Name 
%   is found to be vulnerable to Vulnerability.
url_parameter_vulnerable(Method, Url, FormPairs, Name, Vulnerability) :-
    proxy(Options),
    vulnerability_spike(Vulnerability, Spike),
    spike_url(Url, Spike, Name, SpikedUrl),
    http_do(Method, SpikedUrl, FormPairs, ResponseBody, Options),
    vulnerability_tell(Vulnerability, Tell),
    sub_atom(ResponseBody, _, _, _, Tell).

spike_url(Url, Spike, Name, SpikedUrl) :-
    parse_url(Url, Attributes),
    memberchk(search(Pairs), Attributes),
    select(Name=_, Pairs, Name=Spike, SpikedPairs),
    select(search(Pairs), Attributes, search(SpikedPairs), SpikedAttributes),
    parse_url(SpikedUrl, SpikedAttributes).

http_do(get, SpikedUrl, _, ResponseBody, Options) :-
    http_get(SpikedUrl, ResponseBody, Options).
http_do(post, SpikedUrl, FormPairs, ResponseBody, Options) :-
    http_post(SpikedUrl, form(FormPairs), ResponseBody, Options).

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
