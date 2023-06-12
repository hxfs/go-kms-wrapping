package ukms

import (
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hxfs/go-kms-wrapping/v2"
)

// options = how options are represented
type options struct {
	*wrapping.Options
	withRegion    string
	withAccessKey string
	withSecretKey string
	withProjectId string
	withLogger    hclog.Logger
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	// First, separate out options into local and global
	opts := getDefaultOptions()
	var wrappingOptions []wrapping.Option
	var localOptions []OptionFunc
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case wrapping.OptionFunc:
			wrappingOptions = append(wrappingOptions, o)
		case OptionFunc:
			localOptions = append(localOptions, to)
		}
	}

	// Parse the global options
	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}

	// Don't ever return blank options
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	// Local options can be provided either via the WithConfigMap field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "kms_key_id": // deprecated backend-specific value, set global
				opts.WithKeyId = v
			case "access_key":
				opts.withAccessKey = v
			case "secret_key":
				opts.withSecretKey = v
			case "projectId":
				opts.withProjectId = v
			}
		}
	}

	// Now run the local options functions. This may overwrite options set by
	// the options above.
	for _, o := range localOptions {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, err
			}
		}
	}

	return &opts, nil
}

func getDefaultOptions() options {
	return options{}
}

// WithLogger provides a way to pass in a logger
func WithLogger(with hclog.Logger) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withLogger = with
			return nil
		})
	}
}
