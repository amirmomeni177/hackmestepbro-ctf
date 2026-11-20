# frozen_string_literal: true

require "digest"
require "time"

module Lab
  class WorkspaceData
    BOARD_TITLES = ["Solstice Campaign", "Field Notes", "Orbit Brand System", "Daybreak Packaging",
                    "Northline Lookbook", "Studio Portfolio"].freeze
    WORKSPACES = ["Juniper Studio", "Clover Creative", "Northwind Design", "Aster Studio"].freeze
    ACTORS = ["Mara Vale", "Joss Linn", "Ivo Ren", "Sana Bell", "Rory Chen", "Nia Moss"].freeze
    VERBS = ["left feedback on", "added three images to", "shared"].freeze
    SAMPLE_DATE = Time.utc(2026, 11, 19, 16).freeze

    attr_reader :name, :email, :workspace

    def initialize(user)
      @user_id = user.fetch("id")
      @name = user.fetch("name")
      @email = user.fetch("email")
      random = Random.new(Digest::SHA256.hexdigest(@user_id).to_i(16))
      @workspace = {
        id: "Workspace:#{@user_id}", name: WORKSPACES.sample(random: random),
        plan: "Studio", members_count: random.rand(4..8)
      }
      @boards = BOARD_TITLES.sample(3, random: random).map.with_index do |title, index|
        slug = title.downcase.tr(" ", "-")
        {
          id: "Board:#{@user_id}:#{slug}", slug: "#{slug}-#{@user_id}", title: title,
          updated_at: (SAMPLE_DATE - (index * 24 + random.rand(1..8)) * 3600).iso8601,
          assets_count: random.rand(8..32), cover_hue: random.rand(0...360)
        }
      end
      @activity = ACTORS.sample(@boards.size, random: random).zip(@boards, VERBS).map.with_index do |(actor, board, verb), index|
        { id: "Activity:#{@user_id}:#{index + 1}", actor_name: actor, verb: verb,
          board_title: board.fetch(:title), at: board.fetch(:updated_at) }
      end
    end

    def id
      "User:#{@user_id}"
    end

    def slug
      email.split("@", 2).first
    end

    def sign_in_provider
      "keystone_id"
    end

    def boards(first: 10)
      @boards.take([first || 10, 0].max)
    end

    def activity(first: 10)
      @activity.take([first || 10, 0].max)
    end
  end
end
