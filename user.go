package auth

type User struct {
	Username string       `json:"username" bson:"username"`
	Password string       `json:"password" bson:"password"`
	Salt     string       `json:"salt" bson:"salt"`
	Avatar   string       `json:"avatar" bson:"avatar"`
	Level    int          `json:"level" bson:"level"` //权限等级 0-->admin; 1-->高级用户(agent读写+hub读写)； 2-->agent读写；3-->agent只读；4-->hub读写；5-->hub只读
	Config   []UserConfig `json:"config" bson:"config"`
	Xml      bool         `json:"xml" bson:"xml"`
}

type UserConfig struct {
	Workspace string              `json:"workspace" bson:"workspace"`
	Favor     map[string][]string `json:"favor" bson:"favor"`
}
