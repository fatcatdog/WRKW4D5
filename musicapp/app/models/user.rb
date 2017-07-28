class User < ApplicationRecord
validates :email, :password_digest, :session_token, prescense: true
validates :password, length: { minimum: 6, allow_nil: true }

attr_reader :password

after_initialize :ensure_session_token

def self.find_by_credentials(username, password)
  user = User.find_by(email: email)
  return nil unless user && user.valid_password?(password)
  user
end

def generate_session_token
  SecureRandom.urlsafe_base64(16)
end

def reset_session_token
  self.session_token = generate_session_token
  self.save!
  self.session_token
end

private

def ensure_session_token
  self.session_token ||= generate_session_token
end

end
