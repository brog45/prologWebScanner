:- module(webfuzz,[url_parameter_vulnerable/5, url_form_parameter_vulnerable/4]).

:- use_module(library(http/http_client)).

%!  url_form_parameter_vulnerable(+Url, +FormPairs, -ParameterName, -Vulnerability) is nondet
%   Posts mutated versions of FormPairs to Url and succeeds when parameter named
%   ParameterName is found to be vulnerable to Vulnerability.
%   FormPairs is a list of Name=Value pairs.
url_form_parameter_vulnerable(Url, FormPairs, ParameterName, Vulnerability) :-
    proxy(Options), 
    vulnerability_spike(Vulnerability, Spike),
    select(ParameterName=_, FormPairs, ParameterName=Spike, SpikedFormPairs),
    http_post(Url, form(SpikedFormPairs), Reply, Options),
    vulnerability_tell(Vulnerability, Tell),
    sub_atom(Reply, _, _, _, Tell).

%!  url_parameter_vulnerable(+Method, +Url, +FormPairs, -ParameterName, -Vulnerability) is nondet
%   Tests Url for vulnerable parameters and succeeds when parameter named ParameterName 
%   is found to be vulnerable to Vulnerability.
%   FormPairs is a list of Name=Value pairs.
url_parameter_vulnerable(Method, Url, FormPairs, ParameterName, Vulnerability) :-
    proxy(Options),
    vulnerability_spike(Vulnerability, Spike),
    spike_url(Url, Spike, ParameterName, SpikedUrl),
    http_do(Method, SpikedUrl, FormPairs, ResponseBody, Options),
    vulnerability_tell(Vulnerability, Tell),
    sub_atom(ResponseBody, _, _, _, Tell).

% Given a URL and a Spike value, spike_url/4 succeeds for each parameter 
% named ParameterName from Url and SpikedUrl, where that parameter's value is
% replaced with Spike.
spike_url(Url, Spike, ParameterName, SpikedUrl) :-
    parse_url(Url, Attributes),
    memberchk(search(Pairs), Attributes),
    select(ParameterName=_, Pairs, ParameterName=Spike, SpikedPairs),
    select(search(Pairs), Attributes, search(SpikedPairs), SpikedAttributes),
    parse_url(SpikedUrl, SpikedAttributes).

% send an HTTP request
http_do(get, SpikedUrl, _, ResponseBody, Options) :-
    http_get(SpikedUrl, ResponseBody, Options).
http_do(post, SpikedUrl, FormPairs, ResponseBody, Options) :-
    http_post(SpikedUrl, form(FormPairs), ResponseBody, Options).

% succeeds for each vulnerability and the "spike" test value to use for fuzzing
vulnerability_spike(xss, 'fd<xss>sa').
vulnerability_spike(sqli, 'fd\'sa').

% succeeds for each vulnerability and the "tell" value to test the response for
vulnerability_tell(xss, XssTell) :- vulnerability_spike(xss, XssTell).
vulnerability_tell(sqli, 'error in your SQL syntax').

%! proxy(-Options) is det.
%  Succeeds when Options is the appropriate HTTP options list for the HTTP proxy
%  specified in the http_proxy environment variable.
proxy([proxy(Host:Port)]) :- 
    getenv(http_proxy, Url), 
    parse_url(Url, UrlAttributes), 
    memberchk(host(Host), UrlAttributes), 
    memberchk(port(Port), UrlAttributes), 
    !.
proxy([]).
