package Amon2::Auth::Site::Tumblr;
use 5.008_001;
package Amon2::Auth::Site::Tumblr;

use Mouse;
use Amon2::Auth;
use JSON;
use OAuth::Lite::Consumer;
use OAuth::Lite::Token;

our $VERSION = '0.01';

sub moniker { "tumblr" };

has consumer_key => (
    is => "ro",
    isa => "Str",
    required => 1,
);

has consumer_secret => (
    is => "ro",
    isa => "Str",
    required => 1,
);

has user_info => (
    is => "rw",
    isa => "Bool",
    default => 1,
);

has "consumer" => (
    is => "ro",
    isa => "OAuth::Lite::Consumer",
    lazy_build => 1,
);

sub _build_consumer {
    my ($self) = @_;

    OAuth::Lite::Consumer->new(
        consumer_key => $self->consumer_key,
        consumer_secret => $self->consumer_secret,
        site => "http://www.tumblr.com",
        request_token_path => "/oauth/request_token",
        authorize_path => "/oauth/authorize",
        access_token_path => "/oauth/access_token",
    );
}

sub auth_uri {
    my ($self, $c, $callback_uri) = @_;

    my $request_token = $self->consumer->get_request_token or die $self->consumer->errstr;
    $c->session->set( auth_tumblr => {
            request_token => $request_token->token,
            request_token_secret => $request_token->secret,
        });

    $self->consumer->url_to_authorize( token => $request_token );
}

sub callback {
    my ($self, $c, $callback) = @_;
    my $error = $callback->{on_error};

    my $oauth_verifier = $c->req->param('oauth_verifier') 
        or return $error->("Cannot get a `oauth_verifier' parameter");

    my $session = $c->session->get('auth_tumblr') || {};
    my $token = $session->{request_token};
    my $token_secret = $session->{request_token_secret};

    return $error->("request_token and request_token_secret is required")
        unless $token and $token_secret;

    my $access_token = $self->consumer->get_access_token(
        token => OAuth::Lite::Token->new( token => $token, secret => $token_secret ),
        verifier => $oauth_verifier,
    );

    my @args = ( $access_token->token, $access_token->secret );

    if ( $self->user_info ) {
        my $res = $self->consumer->post("http://api.tumblr.com/v2/user/info");
        return $error->($self->consumer->errstr) if $res->is_error;

        my $data = decode_json $res->decoded_content;

        return $error->($data->{meta}{msg}) unless $data->{meta}{status} == 200;

        push @args, $data->{response}{user};
    }

    $callback->{on_finished}->(@args);
}

no Mouse;
__PACKAGE__->meta->make_immutable();

1;
__END__

=head1 NAME

Amon2::Auth::Site::Tumblr - Tumblr auth integration for Amon2

=head1 VERSION

This document describes Amon2::Auth::Site::Tumblr version 0.01.

=head1 SYNOPSIS

    #config
    + {
        Auth => {
            Tumblr => {
                consumer_key => "...",
                consumer_secret => "...",
            },
        },
    }

    #app
    __PACKAGE__->load_plugin('Web::Auth', {
        module => 'Tumblr',
        on_error => sub {
            my ($c, $error_msg) = @_;
            die $error_msg;
        },
        on_finished => sub {
            my ($c, $token, $token_secret, $user) = @_;
            $c->session->set(tumblr => {
                    user => $user,
                    token => $token,
                    token_secret => $token_secret,
                });
            $c->redirect('/');
        },
    });

=head1 DESCRIPTION

# TODO

=head1 INTERFACE

=head2 Functions

=head3 C<< hello() >>

# TODO

=head1 DEPENDENCIES

Perl 5.8.1 or later.

=head1 BUGS

All complex software has bugs lurking in it, and this module is no
exception. If you find a bug please either email me, or add the bug
to cpan-RT.

=head1 SEE ALSO

L<perl>

=head1 AUTHOR

Soh Kitahara E<lt>sugarbabe335@gmail.comE<gt>

=head1 LICENSE AND COPYRIGHT

Copyright (c) 2012, Soh Kitahara. All rights reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
