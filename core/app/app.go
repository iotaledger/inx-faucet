package app

import (
	"fmt"
	"sort"
	"strings"

	flag "github.com/spf13/pflag"
	"go.uber.org/dig"

	"github.com/gohornet/hornet/pkg/node"
	"github.com/iotaledger/hive.go/configuration"
	"github.com/iotaledger/hive.go/logger"
)

var (

	// AppName is the name of the app.
	AppName = "inx-faucet"

	// Version of the app.
	Version = "0.3.0"

	// configs
	appConfig = configuration.New()

	// config file flags
	configFilesFlagSet = flag.NewFlagSet("config_files", flag.ContinueOnError)
	appCfgFilePath     = configFilesFlagSet.StringP(CfgConfigFilePathAppConfig, "c", "config.json", "file path of the config file")

	InitPlugin *node.InitPlugin
)

func init() {
	InitPlugin = &node.InitPlugin{
		Pluggable: node.Pluggable{
			Name:           "App",
			Params:         params,
			InitConfigPars: initConfigPars,
			Configure:      configure,
		},
		Configs: map[string]*configuration.Configuration{
			"appConfig": appConfig,
		},
		Init: initialize,
	}
}

func initialize(params map[string][]*flag.FlagSet, maskedKeys []string) (*node.InitConfig, error) {

	configFlagSets, err := normalizeFlagSets(params)
	if err != nil {
		return nil, err
	}

	var flagSetsToParse = configFlagSets
	flagSetsToParse["config_files"] = configFilesFlagSet

	parseFlags(flagSetsToParse)

	if err = loadCfg(configFlagSets); err != nil {
		return nil, err
	}

	setDefaultLoggerConfig(appConfig)

	if err := logger.InitGlobalLogger(appConfig); err != nil {
		panic(err)
	}

	fmt.Printf("%s v%s\n", AppName, Version)
	printConfig(maskedKeys)

	return &node.InitConfig{
		EnabledPlugins:  appConfig.Strings(CfgAppEnablePlugins),
		DisabledPlugins: appConfig.Strings(CfgAppDisablePlugins),
	}, nil
}

func setDefaultLoggerConfig(appConfig *configuration.Configuration) {
	var err error
	if err = appConfig.SetDefault(logger.ConfigurationKeyLevel, "info"); err != nil {
		panic(err)
	}
	if err = appConfig.SetDefault(logger.ConfigurationKeyDisableCaller, true); err != nil {
		panic(err)
	}
	if err = appConfig.SetDefault(logger.ConfigurationKeyEncoding, "console"); err != nil {
		panic(err)
	}
	if err = appConfig.SetDefault(logger.ConfigurationKeyOutputPaths, []string{"stdout"}); err != nil {
		panic(err)
	}
}

// parses the configuration and initializes the global logger.
func loadCfg(flagSets map[string]*flag.FlagSet) error {

	if hasFlag(flag.CommandLine, CfgConfigFilePathAppConfig) {
		// app config file is only loaded if the flag was specified
		if err := appConfig.LoadFile(*appCfgFilePath); err != nil {
			return fmt.Errorf("loading config file failed: %w", err)
		}
	}

	// load the flags to set the default values
	if err := appConfig.LoadFlagSet(flagSets["appConfig"]); err != nil {
		return err
	}

	// load the env vars after default values from flags were set (otherwise the env vars are not added because the keys don't exist)
	if err := appConfig.LoadEnvironmentVars(""); err != nil {
		return err
	}

	// load the flags again to overwrite env vars that were also set via command line
	if err := appConfig.LoadFlagSet(flagSets["appConfig"]); err != nil {
		return err
	}

	return nil
}

func hasFlag(flagSet *flag.FlagSet, name string) bool {
	has := false
	flagSet.Visit(func(f *flag.Flag) {
		if f.Name == name {
			has = true
		}
	})
	return has
}

func getList(a []string) string {
	sort.Strings(a)
	return "\n   - " + strings.Join(a, "\n   - ")
}

// prints the loaded configuration, but hides sensitive information.
func printConfig(maskedKeys []string) {
	appConfig.Print(maskedKeys)

	enablePlugins := appConfig.Strings(CfgAppEnablePlugins)
	disablePlugins := appConfig.Strings(CfgAppDisablePlugins)

	if len(enablePlugins) > 0 || len(disablePlugins) > 0 {
		if len(enablePlugins) > 0 {
			fmt.Printf("\nThe following plugins are enabled: %s\n", getList(enablePlugins))
		}
		if len(disablePlugins) > 0 {
			fmt.Printf("\nThe following plugins are disabled: %s\n", getList(disablePlugins))
		}
		fmt.Println()
	}
}

// adds the given flag sets to flag.CommandLine and then parses them.
func parseFlags(flagSets map[string]*flag.FlagSet) {
	for _, flagSet := range flagSets {
		flag.CommandLine.AddFlagSet(flagSet)
	}
	flag.Parse()
}

func normalizeFlagSets(params map[string][]*flag.FlagSet) (map[string]*flag.FlagSet, error) {
	fs := make(map[string]*flag.FlagSet)
	for cfgName, flagSets := range params {

		flagsUnderSameCfg := flag.NewFlagSet("", flag.ContinueOnError)
		for _, flagSet := range flagSets {
			flagSet.VisitAll(func(f *flag.Flag) {
				flagsUnderSameCfg.AddFlag(f)
			})
		}
		fs[cfgName] = flagsUnderSameCfg
	}
	return fs, nil
}

func initConfigPars(c *dig.Container) {

	type cfgResult struct {
		dig.Out
		AppConfig *configuration.Configuration `name:"appConfig"`
	}

	if err := c.Provide(func() cfgResult {
		return cfgResult{
			AppConfig: appConfig,
		}
	}); err != nil {
		InitPlugin.LogPanic(err)
	}
}

func configure() {
	InitPlugin.LogInfo("Loading plugins ...")
}
