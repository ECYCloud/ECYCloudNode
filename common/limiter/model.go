package limiter

type GlobalDeviceLimitConfig struct {
	Enable        bool   `mapstructure:"Enable"`
	RedisNetwork  string `mapstructure:"RedisNetwork"` // tcp or unix
	RedisAddr     string `mapstructure:"RedisAddr"`    // host:port, or /path/to/unix.sock
	RedisUsername string `mapstructure:"RedisUsername"`
	RedisPassword string `mapstructure:"RedisPassword"`
	RedisTLS      bool   `mapstructure:"RedisTLS"`
	RedisCAFile   string `mapstructure:"RedisCAFile"` // empty: RedisCA, then system roots
	RedisCA       string `mapstructure:"-"`           // PEM delivered by the panel
	RedisDB       int    `mapstructure:"RedisDB"`
	Timeout       int    `mapstructure:"Timeout"`
	Expiry        int    `mapstructure:"Expiry"` // second
}
