use inc::Module::Install;
use Module::Install::AuthorTests;

all_from 'lib/Amon2/Auth/Site/Tumblr.pm';


test_requires 'Test::More'     => '0.88';
test_requires 'Test::Requires' => '0.06';

auto_set_repository;

requires 'Amon2::Auth';
requires 'JSON';
requires 'Mouse';
requires 'OAuth::Lite';

tests_recursive;
author_tests 'xt';
WriteAll;
